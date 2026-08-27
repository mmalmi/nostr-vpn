# Changelog

All notable changes to this project are documented in this file.

## 4.1.9 - 2026-08-28

### Release notes

Cashu paid exits now connect, recover, and bill reliably with either manual or
automatic selection.

- Strengthened Selling Internet settings and release coverage on every
  platform that supports acting as a paid exit.
- Improved paid-route activation, health checks, DNS safety, and recovery from
  interrupted or rotated Cashu channels.

### Added

- Add exact shipped-GUI release checks for saving, enabling, restarting, and
  restoring paid-exit seller price, country, and accepted mints on Linux and
  macOS, the platforms where selling internet is supported.
- Add a production-path automatic paid-exit E2E alongside the manual E2E,
  proving signed offer discovery, tunnel-bound health, automatic Cashu
  funding, routed traffic, and streaming seller payments.

### Fixed

- Fund paid exits before relying on billable routing, bind automatic health
  checks to the paid tunnel, bound failed connection and payment retries, and
  preserve the selected Internet mode during cancellation and fallback.
- Refresh and select Cashu keysets for the wallet's exact currency unit before
  channel funding, so mints exposing several active units cannot reject an
  otherwise valid paid-exit purchase.
- Recover delayed, cancelled, and orphaned Spilman channels and refund proofs
  across daemon restarts and mint key rotation without losing funded value.
- Keep Cashu control traffic outside the macOS paid tunnel, preserve MagicDNS
  after paid-exit fallback, and fail closed when safe exit DNS is unavailable.
- Retry one transient authenticated DNS request before failing closed, avoiding
  a cached resolver outage when a provider connection is briefly interrupted.
- Keep the daemon responsive while its owned Cashu wallet repairs or recovers,
  and retry funded paid routes without activating an unverified exit.
- Allow an active paid seller's Direct-to-WireGuard upstream transition to
  finish before the configuration deadline, avoiding a false rollback while
  the replacement tunnel is being proven.
- Grant StartOS packages virtual networking access for `/dev/net/tun` and
  `CAP_NET_ADMIN`, validate the permission in signed release artifacts, and
  restore StartOS/Umbrel image builds after vendoring `cashu-service`.
- Prefer authenticated UDP for the public native FIPS seeds while retaining
  WSS as a fallback on UDP-blocked networks, and migrate prior WSS-only native
  defaults without making the WebSocket transport dial independently. Resolve
  UDP hostnames before selecting a family-specific local socket.
- Update to FIPS 0.4.66, which re-arms an authenticated direct-path handshake
  after repeated network outages or source-address changes, avoiding a full
  handshake-timeout stall when the underlay returns.
- Deliver the signed roster when an admin accepts an inbound device request,
  so the joining device completes instead of remaining at the approval prompt.
- Print join-request reachability once, keep the approval wait quiet through
  transient connectivity changes without polling the daemon, and stop creating
  a replacement request immediately after approval.
- Expand public FIPS WebSocket seed capacity so ordinary browser clients retain
  admission headroom as the authenticated public mesh grows, and evict
  persistently poisoned end-to-end sessions so seed receive loops recover.
- Close a browser's physical WebSocket after its authenticated route becomes
  link-dead, allowing WebVM to reconnect instead of waiting forever on an
  orphaned carrier after approval.
- Show the complete underlying cause chain in native app action errors instead
  of hiding useful wallet, service, and network diagnostics behind a generic
  top-level message.

## 4.1.8 - 2026-08-18

### Release notes

Reliability improvements for discovery and recovery across every platform.

- Improved paid-exit and peer discovery through more resilient public
  WebSocket bootstrap peers.
- Restored authenticated private-mesh sessions after complete network path
  loss without requiring an app or daemon restart.

### Fixed

- Keep public FIPS WebSocket bootstrap listeners responsive under connection
  pressure by expanding their bounded inbound budget and evicting idle clients
  after one missed transport-ping cycle.
- Refresh Cashu wallet keysets before paid-channel funding so mint key rotation
  consolidates proofs into the current keyset instead of rejecting the purchase.
- Stage FIPS wake recovery until the underlay is ready, then replace stale
  carriers after total path loss so authenticated traffic resumes cleanly.
- Keep release verification aligned with the sealed FIPS dependency versions
  and make fleet source-equivalence fixtures work in shallow clones.
- Shorten release verification by reusing signed mobile artifacts and proven
  network setup while retaining physical-device DNS, reconnect, and recovery checks.
- Update HTTP/2 framing to h2 0.4.16 to bound empty DATA frame handling.

## 4.1.7 - 2026-08-10

### Release notes

Reliability improvements and basic feature fixes across every platform.

- Fixed paid-exit discovery, provider links, and connection status.
- Simplified pricing to one per-GB rate with optional fiat display.
- Improved selling, settlement, and reselling Direct, WireGuard, or private-exit Internet.

## 4.1.6 - 2026-08-06

### Release notes

Reliability improvements and basic feature fixes across every platform.

- Improved exit-node discovery and connection reliability in native apps.
- Improved VPN service startup and single-instance behavior.
- Simplified device joining; QR and manual joining remain available.

## 4.1.5 - 2026-08-01

### Release notes

Reliability improvements and basic feature fixes across every platform.

- More reliable exit nodes, DNS settings, Direct mode, and network switching.
- Fixed QR and manual joining across mobile and desktop; mobile QR codes are larger.
- Improved app, VPN-service, and paid-exit recovery.

### Added

- Add exact signed-release gates on physical Android and iOS for WireGuard
  exit routing, every DNS policy, native Internet/DNS restoration, repeated
  background/foreground and rapid start/stop, real Wi-Fi radio OFF→ON recovery
  with no physical fallback, exact original-Wi-Fi restoration, fresh DNS,
  WireGuard and reverse-payload recovery within four seconds, and QR and manual
  joining in both device roles.
- Add real macOS, Windows, and Linux gates for underlay changes, WireGuard exit
  cleanup, native route/DNS recovery, service lifecycle, and exact dual-family
  listener ownership.
- Add an exact-artifact, transactional fleet rollout with frozen roster and
  machine identities, restart/network verification, and verified rollback.

### Fixed

- Prevent libc/NSS DNS from bypassing nVPN on systemd-resolved uplink-mode
  hosts, with token-owned resolver paths and crash-safe restoration.
- Rebind FIPS underlay carriers in place across hotspot, Wi-Fi, and interface
  changes while preserving the endpoint and authenticated sessions, carrying
  payload through mesh fallback while direct paths recover.
- Restore device-native routes and DNS after exit-node or private-tunnel
  shutdown on every platform, and fail closed when owned network state cannot
  be cleaned up.
- Wait for the exact Windows daemon process to become control-ready, report a
  reload successful only after WireGuard routes and DNS are active, and bound
  native operations with owned rollback so Direct restoration cannot hang;
  ignore stale daemon PID records reused by unrelated processes and keep the
  exclusive singleton lock authoritative during startup.
- Keep the Windows UDP DNS stub alive when a late reply to an expired client
  port produces `WSAECONNRESET`, so switching encrypted DNS providers cannot
  silently stop subsequent lookups.
- Stream Linux WireGuard apply and rollback configuration directly to `wg`
  without filesystem secret files, so exit nodes work under the stock
  enforced Ubuntu AppArmor policy.
- Derive and pin the Linux endpoint-bypass source address when a replacement
  default route omits `prefsrc`, keeping FIPS, WireGuard, DNS, and HTTPS on the
  new underlay.
- Bind macOS WireGuard UDP sockets to the selected physical interface before
  the first handshake, then migrate that binding across Wi-Fi/hotspot changes
  while the split-default kill switch stays installed.
- Route macOS exit DNS through an owned System Configuration resolver state
  so ordinary system lookups use the secure local stub, with transactional
  rollback and crash cleanup.
- Track exact macOS route ownership, preserve foreign routes, and retain the
  cleanup journal whenever route, DNS, forwarding, or WireGuard teardown is
  incomplete.
- Parse transport-tagged FIPS WebSocket endpoints into a valid iOS Packet
  Tunnel remote host instead of passing the transport prefix to Network
  Extension.
- Complete QR and manual joins only after the joining device applies the
  signed roster, support both admin/joiner directions across desktop and
  mobile, surface delivery-start failures without losing the durable approval,
  and make mobile QR codes use the available screen width.
- Keep join, roster, and control delivery progressing during network-settle
  sampling so a scanned or manually entered phone join cannot stall behind an
  unrelated underlay event.
- Close the web requester’s QR/link screen only after it activates the
  admin-signed network, and require the authenticated Umbrel release gate to
  prove both the scanner roster and requester-side transition.
- Replace prior Android installs in place, reject parallel package variants,
  and prevent duplicate VPN service/process ownership.
- Route Android's embedded encrypted DNS through an active WireGuard exit,
  and cancel in-flight resolver work when the tunnel stops so it cannot fall
  through to restored device Internet.
- Avoid treating Android's first VPN-service network snapshot as a roam, so
  startup performs the required underlay handshake without unnecessarily
  resetting established FIPS sessions.
- Refresh Android's WireGuard path again when a newly available Wi-Fi network
  becomes Internet-validated, avoiding timer-delayed recovery after Wi-Fi
  OFF→ON transitions.
- Serialize Android native tunnel startup and cancel obsolete generations,
  preventing rapid connect/disconnect from reviving or leaking a stopped VPN.
- Stop foreground Android status polling from rebuilding tunnel configuration
  or recomposing unchanged state, reducing exact Release VPN-off idle CPU from
  6.30% to 1.48% in the physical 60-second gate.
- Expose the iOS VPN switch as one accessible control while retaining its
  native action, enabled state, label, and value.
- Keep macOS configuration editable while an installed background service is
  disabled or stopped, without bypassing daemon-owned saves while it is active.
- Release the iOS UI process's shared Cashu wallet and SQLite locks before
  suspension, then reopen the native core on foreground, preventing
  RunningBoard `0xDEAD10CC` terminations.
- Keep the iOS packet tunnel's runtime-state sidecar anchored to its private
  configuration after launch, so background operation remains fresh and
  foregrounding cannot stop a healthy tunnel based on stale state.
- Resolve Ad Hoc signing from the exact selected CoreDevice instead of a stale
  environment UDID when multiple iPhones are connected.
- Release completed FIPS-TCP state-control slots promptly so periodic roster
  and capability traffic cannot starve a manual-join roster or its durable
  application receipt behind the per-peer connection budget.
- Pace the quiet FIPS-TCP control loop at its close-retention deadline instead
  of the active retransmission cadence, while keeping commands, packets, and
  open records immediately responsive.
- Upgrade FIPS to 0.4.53 so physical-interface changes reauthenticate UDP
  peers at the safe handshake interval, replace stale WebSocket carriers
  immediately without ordinary reconnect backoff, reject pre-rebind handshakes,
  preserve routed npub sessions and wire compatibility across recovery, and
  bind exact same-port IPv4 and IPv6 carriers without ambiguous delivery while
  avoiding redundant discovery when a healthy routed fallback already carries
  the established session, while bounded discovery turns preserve payload,
  control-query, and graceful-shutdown progress under sustained pressure.
- Repair Cashu paid-exit close, settlement, and refund recovery across
  historical or retried proofs on platforms where the feature is available.
- Update the Nostr and Linux property-list parser locks to reject malformed
  NIP-04 initialization vectors and adversarial XML without panicking or
  unbounded parser work.

### Changed

- Build one frozen iOS archive, test an Ad Hoc export from that exact archive
  on the physical phone, and export the App Store upload from the same sealed
  artifact.
- Run resource-isolated Windows, macOS, Linux, Android, Rust, and Docker lanes
  concurrently, then keep roaming, performance, and idle-CPU measurements
  serial for stable release results.
- Keep the iOS wallet and paid-exit implementation out of the shipped UI and
  runtime while retaining shared compatibility data, and prepare truthful
  worldwide App Store metadata with every territory enabled.
- Gate physical iOS releases with three background/foreground cycles,
  including a ten-second suspension, and verify native-core close/reopen state
  on every transition.
- Verify Android Activity background/foreground survival in every physical
  Android smoke.
- Build the signed macOS and Linux release candidates on the release Mac once,
  verify their exact source and bytes, and import them into the macOS and Linux
  VMs; reuse a separately sealed host-built Linux fixture peer for the Linux
  and Windows network gates while keeping the Windows release build native.
- Pin every macOS release gate to the disposable UTM guest identity so a
  misconfigured SSH alias cannot change the release Mac's routes or DNS.
- Keep ARMv6 out of the public release and release gate; build it separately
  only when updating the private fleet.

## 4.1.4 - 2026-07-22

### Changed

- Reuse one verified iOS device build across physical idle, WireGuard exit,
  and phone-to-phone join lanes instead of rebuilding it for every lane.
- Record the release gate against a 30-minute warm-run wall-clock target while
  keeping contention-sensitive performance and physical-device checks serial.
- Preserve reusable Docker build metadata for the shared node and Linux GUI
  images, and route final Windows packaging through the configured SSH jump.
- Exercise every exit-DNS settings option through saved configuration and the
  native mobile packet path, and require a physical Android device for the
  Android/iOS WireGuard exit gate instead of silently accepting an emulator.

### Fixed

- Restore manual out-of-band network joining on Android, iOS, macOS, Windows,
  Linux, web, and CLI: the joining device can enter the admin Device ID and
  Network ID, while the admin can share those values and add the joiner's
  Device ID.
- Cover both the signed join-request flow and the explicit manual flow on both
  sides in the cross-platform release gate.
- Deliver a mobile QR approval from the durable outbox through the running
  tunnel instead of leaving it queued forever, and restart Android/iOS tunnels
  after approval and roster changes.
- Retry idempotent join-roster delivery while a newly started mobile route is
  forming, while treating only the joiner's durable application receipt as
  success, so manual joins complete in seconds in either phone direction.
- Use one roster-application path on desktop and mobile, and gate both
  desktop-admin/mobile-joiner and mobile-admin/desktop-joiner receipt flows.
- Carry an admin-signed roster into sandboxed mobile tunnel launches so manual
  admin-side additions propagate on both Android and iOS.
- Gate physical QR approval in both directions between iOS and Android, using
  the real action, tunnel restart, signed-roster delivery, receipt, and config
  handoff paths; exercise both mobile admin/joiner combinations for manual
  out-of-band joining in the same physical gate.
- Always await and verify physical iOS packet-tunnel cleanup, including failed
  probes, and refuse an in-place development build replacement while the
  installed app cannot confirm that its tunnel is off.
- Stop Android's VPN service on every explicit disconnect action, even when a
  backgrounded activity has stale UI state after a long-running tunnel test.

## 4.1.3 - 2026-07-22

### Added

- Add one cross-platform exit DNS policy with automatic WireGuard-profile DNS,
  built-in or custom encrypted DNS, and explicit DNS-through-exit options.
- Add physical Android and iOS WireGuard exit release coverage that proves
  provider-side forwarding, profile DNS, public Internet access, TUN traffic,
  and native device DNS/Internet restoration after disconnect.

### Changed

- Shorten release validation by running the remote Windows lane and one shared
  Docker image build alongside host checks, then overlapping subnet-isolated
  NAT and kernel/userspace WireGuard fixtures while keeping roaming, throughput,
  device, and idle-CPU measurements contention-free and serial.
- Add a focused loaded-latency scenario so performance outliers can be repeated
  without paying for the full roaming and network-change suite.

### Fixed

- Restore the original Direct route and DNS ownership after WireGuard and
  private-exit transitions on macOS and Windows without disturbing scoped VPN
  routes or the WireGuard endpoint's underlay route.
- Keep daemon reload acknowledgements and offline paid-exit retries from
  delaying tunnel maintenance and route convergence.
- Keep iOS physical-device debug signing independent from the App Store
  distribution identity used by release uploads.
- Reduce joined iOS onboarding polling so an idle app stays within the mobile
  CPU release budget.
- Build Windows release and smoke-test artifacts away from the live service,
  and fail instead of reusing an installer after a nested build error.

## 4.1.2 - 2026-07-21

### Fixed

- Deliver signed QR join approvals immediately instead of waiting for the next
  daemon heartbeat, and refresh mobile onboarding promptly once the joined
  network is ready.
- Keep the authenticated mobile onboarding route alive while switching to the
  joined network scope so the new configuration can be acknowledged reliably.
- Avoid duplicate macOS daemon reloads after applying a configuration change.
- Refresh signed hashtree release roots from relays even when the local pubsub
  cache contains an older valid root.

## 4.1.1 - 2026-07-21

### Fixed

- Restore the native Windows build after the shared exit-route and roster
  delivery paths were extended for the FIPS roaming repair.

## 4.1.0 - 2026-07-21

### Changed

- Replace network invitations and manual device entry with one signed
  join-request flow across desktop, mobile, web, CLI, and nearby pairing.
- Enable paid exits in standard release builds, mark automatic paid internet
  as experimental, and leave exit fail-closed behavior off by default.
- Replace the mutually exclusive byte/time/packet tariff with a version 2,
  byte-only paid-exit offer. Prices are normalized per GB and also show how
  much data one satoshi buys.

### Fixed

- Publish the local signed FIPS endpoint advert through the shared Nostr
  pubsub provider so discovered internet sellers can actually be reached.
- Make GUI purchases select and start the bought exit, show active and error
  states, and keep the ordinary internet route available until a non-strict
  selected exit is connected.
- Update the integrated FIPS core to 0.4.34 so repeated network roams converge
  stale direct routes, asymmetric reconnects, same-path rekey races, and
  orphaned responder rekeys without accepting FMP control heartbeats as direct
  FSP payload validation or applying delayed outage loss reports to a newly
  restored carrier.
- Update `nostr-pubsub-fips` to 0.4.5.
- Reserve the bounded public-ingress discovery budget for paid-exit sellers so
  ambient peers cannot exhaust the small endpoint budget and deny fresh WebVM
  clients before their first `.fips` lookup.
- Create the OpenRC secure-DNS resolver file when a minimal guest image has no
  prior `/etc/resolv.conf`, preserving direct `.fips` resolution on first boot.

## 4.0.99 - 2026-07-19

### Fixed

- Attach `.fips` DNS and host IPv6 networking to the ordinary authenticated
  FIPS endpoint and VPN interface instead of starting a second disconnected
  node. DNS-resolved peer identities now enter the bounded identity cache
  before packets use the standard discovery, routing, and session pipeline.
- Keep the ordinary VPN tunnel alive when `.fips` host access is disabled,
  while removing only its host IPv6 address, route, DNS, and firewall state.
- Install and restore the local authenticated DNS resolver on OpenRC Linux
  hosts as well as systemd-resolved and container environments.
- Allow authenticated `.fips` ICMPv6 echo diagnostics while retaining the
  host firewall's default-deny policy for other non-TCP overlay traffic.
- Route explicitly resolved `.fips` identities through an already-admitted
  physical FIPS adjacency under both configured-only and Open discovery,
  without granting ambient learned identities the same fallback transit.
- Keep standard FIPS pubsub subscriptions stable when an authenticated peer
  moves to a replacement link, avoiding full retained-event replay to every
  peer while preserving catch-up for newly connected identities.
- Retain queued device approvals until the authenticated guest confirms that
  the exact signed roster was applied, with idempotent retries after lost
  transport records or application receipts.
- Keep routed FSP establishment on its authenticated reply-learned seed path
  through the final Noise handshake message, and ignore stale session errors
  from unrelated seed branches while that path remains healthy.
- Keep ambient open-discovery retries bounded and cooldown-aware, skip retry
  work for already-authenticated WebSocket adjacencies, and reserve transit
  loop-check bypass for the bounded route proven by a verified lookup response
  rather than every learned path.
- Cool unaffiliated peers learned from public relay announcements for thirty
  minutes after three failed connection attempts, while preserving unlimited
  reconnect for configured and roster peers.
- Apply that same bounded cooldown when an ambient transport accepts the probe
  but the remote endpoint never completes its authenticated FIPS handshake.
- Delay the first macOS automatic update check for ten seconds after startup
  so networking can settle, then retry failures after one minute instead of
  silently waiting for the normal six-hour polling interval.

## 4.0.98 - 2026-07-19

### Added

- Added a production topology regression that delivers an ordinary signed
  join roster through explicit WSS seeds, a generic FIPS router, and a
  zero-preconfigured physical guest.
- Made LAN discovery an explicit persisted network setting while retaining
  repeatable daemon flags for Ethernet interface and discovery scope.

### Changed

- Integrated the existing StartOS package into the release gate and both
  release pipelines. Tagged releases now publish signed, manifest-validated
  x86_64 and aarch64 `.s9pk` artifacts alongside the native apps.
- Use standard port-7368 Nostr pubsub as the sole FIPS peer/service
  announcement path; public Nostr relays carry bounded signed events, never
  FIPS packet records or WebRTC signaling envelopes.
- Updated FIPS Core and Endpoint to 0.4.14 and `nostr-pubsub-fips` to 0.4.3
  for routed WSS first contact, verified-event reuse, bounded observed-ID
  caches, provider abuse cooldowns, reverse-session transit, and idle-work
  fixes.

### Fixed

- Admit authenticated physical adjacencies while an ordinary device approval
  is pending and accept authenticated in-FIPS WebRTC offers without a public
  relay fallback.
- Bound public-relay and FIPS retained replay, preserve already verified
  control events across policy checks, and expose pubsub wire, TCP, and
  provider-cooldown counters.
- Stop repeated idle control-plane scans, disabled-host cleanup, duplicate
  Linux address handling, and route-refresh feedback loops.
- Fully stop LAN mDNS between aligned discovery windows, preserving periodic
  local peer discovery while removing the persistent Android VPN wakeup loop.

## 4.0.97 - 2026-07-18

### Added

- Added paired `nvpn daemon` options for scoped raw-Ethernet FIPS discovery
  and adjacency while keeping ordinary join requests and roster approval on
  the standard control path.
- Added repeatable authenticated FIPS WebSocket seed URLs and an optional
  bounded native plain-WS listener for deployment behind a TLS reverse proxy.
  URL-only seeds provide the first adjacency without a preconfigured peer
  identity.
- Added a single-owner CDK 0.17.3 Cashu wallet runtime with exact legacy-seed
  migration into the existing iOS Keychain and Android Keystore facilities,
  cross-process writer exclusion, startup recovery, and SQLite WAL-family
  preservation without database-at-rest encryption.

### Changed

- Removed the kind-21060 Nostr relay FIPS packet carrier and its direct relay
  adapter. Configured Nostr relays remain available to standard
  `nostr-pubsub` for low-rate signed peer/service announcements and ordinary
  events; physical FIPS records use WebSocket, WebRTC, Ethernet, UDP, TCP, or
  Tor links.
- Moved control pubsub onto the standard port-7368 `nostr-pubsub-fips`
  service. Normal `REQ`/`EVENT`/`CLOSE` frames remain intact, while grouped
  `INV` and single-event `WANT` frames globally deduplicate both live delivery
  and stored replay across FIPS, Hashtree indexes, and ordinary Nostr relays.
- Removed the obsolete platform-specific guest runtime and kept browser-based
  joining on the ordinary nVPN daemon and signed-roster approval flow.
- Moved native wallet operations from short-lived CLI processes onto the
  application-owned CDK repository and updated `cdk-spilman` to 0.17.0.
- Normalize wallet mint URLs and discard invalid or unsupported mint entries
  before selecting a default mint.
- Updated FIPS Core and Endpoint to 0.4.11, `nostr-pubsub` to 0.1.13, and
  `nostr-pubsub-fips` to 0.4.1 for the bounded WebSocket physical transport,
  reliable routed pubsub, relay-packet-carrier removal, and URL-only first
  adjacency.

### Fixed

- Skip Linux interface and firewall reconciliation when the normalized FIPS
  endpoint-bypass host set is unchanged, avoiding repeated route-tool process
  launches during idle state refreshes.
- Keep ephemeral kind-37195 FIPS peer adverts live in memory without rewriting
  them into the durable control-event cache on every refresh.
- Keep reliable FIPS pubsub idle when no authenticated peer is eligible: retain
  signed events in the bounded store/outbox and replay them when a subscribed
  peer arrives instead of spinning a rejected-publish queue.
- Probe every due roster peer during each heartbeat so one peer cannot starve
  liveness updates for the rest of the roster.
- Keep authenticated in-FIPS WebRTC negotiation available when public Nostr
  discovery is disabled, and resolve roster actions against the active network
  consistently.
- Run the CDK wallet service on its own worker so asynchronous hosts such as
  `nostr-vpn-web` can open, use, and close it without nested-runtime failures.
- Activate the private control runtime for an ordinary pending device-approval
  join and safely reload a running daemon after persisting a new join request.
- Preserve an intentionally paused running daemon during exact GUI join
  approval while still queueing and delivering the signed roster.

## 4.0.96 - 2026-07-16

### Changed

- Moved join requests, signed roster updates, capabilities, and paid-route
  control records onto the existing wire-compatible FIPS-TCP 0.2.0 stream.
  Only ping/pong probes remain on the FIPS datagram path.
- Reduced first-join approval to one ordinary signed roster plus the existing
  one-time QR request secret in the encrypted nVPN control record. Removed the
  identity receipt/context batch, forwarding and apply-ACK envelopes, custom
  replay/retry machinery, and relay fallback; an unsuccessful join uses the
  normal join-request flow again.
- Updated embedded FIPS Core and Endpoint to 0.4.6 for bounded production
  control polling and corrected no-wire routing/session behavior.

### Fixed

- Apply a complete FIPS-TCP control record as soon as its bytes arrive instead
  of depending on a later stream-close frame.
- Reduce idle control-runtime wakeups while keeping inbound records and local
  publish commands event-driven.
- Retain completed FIPS-TCP control records under bounded local receive-queue
  backpressure instead of dropping them after transport acknowledgement.
- Avoid oversized async test futures on worker stacks in the mobile FIPS
  integration fixture.
- Invalidate a different Linux underlay default route before installing a
  WireGuard-exit default, preventing activation-time route clones from
  bypassing the encrypted upstream, while keeping the FIPS underlay snapshot
  stable when the managed WireGuard interface becomes the system default.

## 4.0.95 - 2026-07-16

### Changed

- Added the application-owned FIPS Nostr-relay carrier to desktop, mobile, and
  headless endpoints as a priority-250 fallback for explicit roster and
  approval peers. Direct UDP, TCP, and WebRTC links remain application-owned
  and independently active.
- Updated the embedded FIPS Core and Endpoint crates from 0.4.4 to exact
  published 0.4.5 for bounded TCP/Tor FSP record framing, deterministic
  simultaneous stream convergence, endpoint send-receipt correlation, and
  tree-dependent Bloom-filter convergence. FMP, FSP, discovery, and the
  application-owned UDP roster path are unchanged.

### Fixed

- Restored the Windows all-target build by correctly scoping Unix-only tests
  and helpers.
- Kept the macOS QR scanner buildable with the release workflow's Xcode 15.4
  toolchain while retaining the macOS 26 Cinematic Video crash safeguard.

## 4.0.94 - 2026-07-16

### Changed

- Replaced Nostr VPN's private reliable record carrier and Inv/WANT wrappers
  with the shared `nostr-pubsub-fips` TCP/FIPS driver while preserving the
  `nvpn.control.pubsub/1` service, 56 KiB event bound, application-owned UDP
  roster links, standalone operation, and bounded reconnect replay.
- Updated desktop, mobile, Linux, and WebRTC configuration to exact published
  FIPS Core and Endpoint 0.4.1 and Nostr identity storage 0.4.0. Authenticated
  FIPS sessions now carry link negotiation without the removed direct-message
  and signaling-relay fields, and WebRTC reconnect tolerates individually
  unavailable mDNS candidates.
- Added a two-process product gate that moves roster traffic in both directions
  over explicitly configured UDP links while a signed control event traverses
  the shared TCP/FIPS pubsub service.

### Fixed

- Treat an authenticated FIPS link-id change as a pubsub stream reconnect, so
  cached control events replay after a peer process or endpoint restarts.
- Fail closed on peer-policy errors instead of converting policy failures into
  unknown-but-eligible peers, while explicit unknown peers remain eligible
  under the default shared reputation policy.

## 4.0.93 - 2026-07-14

### Changed

- Control-event pubsub now carries bounded framed records over TCP/FIPS 0.1.0.
  Persistent peer streams provide ordered retransmission, replacing the local
  three-attempt `Inventory`/`Want` datagram retry layer while reconnects
  resubscribe the cached update root.

### Fixed

- Native wallets no longer show placeholder balances or routine exchange-rate
  refresh labels, render Lightning top-up invoices as QR codes, and
  automatically claim paid invoices while the receive flow is open.

## 4.0.92 - 2026-07-13

### Changed

- Simplified the native wallet on every platform: zero balances no longer
  clutter navigation, fiat display controls live in Settings and remain
  default-on, and Lightning receive/send requires a configured mint instead of
  silently choosing one. Pasted or scanned Cashu tokens are parsed locally and
  reviewed with their amount and mint before redemption; failed redemption
  keeps or follows the confirmation with the mint error.
- Exit routes now force public DNS through a local fail-closed stub on Linux,
  macOS, Windows, Android, and iOS. MagicDNS stays local. A selected
  WireGuard exit uses only that profile's configured DNS through the encrypted
  WireGuard path; other exits use authenticated DNS-over-HTTPS and never expose
  or trust underlay resolvers.
- Updated to FIPS Core 0.3.93 and Endpoint 0.3.60 so busy relays retain the
  first authenticated application packet until session ownership is installed.
- Desktop and CLI update checks consume the latest signed Hashtree release root
  from the shared FIPS/relay pubsub cache before opening a direct relay path.
- Relay bridges subscribe to the exact update publisher/tree, and nodes replay
  the bounded latest root to FIPS peers that connect after publication.
- Bumped to FIPS Core 0.3.89 and Endpoint 0.3.58, with simpler direct endpoint
  receive and send batching while preserving the FIPS protocol surface.
- Enabled the paid-exit marketplace in default CLI, daemon, and native-app
  builds; sharing internet as a seller remains opt-in.

### Fixed

- Added buyer-side stateful ingress filtering for selected FIPS exits: only
  replies to locally originated flows and narrowly valid ICMP errors are
  admitted, while unsolicited, malformed, private, loopback, link-local, and
  spoofed mesh-source traffic is dropped for IPv4 and IPv6.
- Hardened the appliance web control surface by refusing non-loopback binds
  unless an authenticated platform proxy is declared, enforcing same-origin
  browser requests, preventing API caching, and keeping WireGuard credentials,
  full configurations, and raw network or nearby-pairing invites out of web
  responses.
- Signed LAN-pairing announcements with the device's Nostr identity and reject
  unsigned, stale, replayed, tampered, or signer/admin-mismatched packets.
- Updated the plist/XML dependency chain to remove the affected quick-xml
  versions reported by the Rust security advisory database.
- Removed debug-only desktop and mobile UI gates that hid the paid-exit market,
  wallet, and seller controls from release builds despite backend support being
  enabled by default.
- Restored joining-device request links and QR approval as the onboarding flow;
  legacy network-invite commands remain hidden for migration compatibility.
- Added `nvpn join-request`, which reuses the pending request, shows live FIPS
  reachability changes, waits for approval by default, and rotates only with
  explicit `--reset`.
- Pending native-app join requests now receive and apply signed approvals from
  the approval relay, so accepted iPhone and Android devices automatically gain
  the network roster instead of remaining on the join screen.
- macOS now describes manual pairing as a supported pairing path instead of
  incorrectly labeling it as legacy.
- Learned private-LAN mobile endpoint hints now regain their private-path
  priority without overriding the explicit priority of static peer hints.

## 4.0.90 - 2026-07-10

### Changed

- Bumped to FIPS Core 0.3.87 for authenticated reverse-hop routed session
  establishment, and aligned WebRTC with the configured private-mesh MTU.

### Fixed

- Enabled and restored macOS IPv4 forwarding for exit-node operation, loaded
  nvpn PF rules into a directly evaluated Apple anchor, and preserved the real
  underlay default route across tunnel restarts.

## 4.0.89 - 2026-07-08

### Changed

- Bumped to FIPS 0.3.81/0.3.56 for the routed endpoint-payload fix used by
  the FIPS routed UDP Docker gate.
- Simplified direct endpoint receive batching by finalizing already-admitted
  packet batches without revalidating them against later mesh snapshots.

### Fixed

- Reworked device linking so joined/admin apps no longer show their own join
  request QR, admins scan or paste join requests directly, nearby discovery
  advertises devices that want to join, requester device names are preserved,
  and the macOS app carries the camera entitlement needed for QR scanning.
- Preserved explicit static non-roster FIPS transit endpoints when Nostr
  discovery is disabled, while still keeping them out of private-network routes.
- Hardened the FIPS routed UDP release gate to wait for FIPS-routed peer
  reachability and use the relay path exercised by this release candidate.

## 4.0.88 - 2026-07-08

### Added

- Added the public iOS App Store download link alongside the TestFlight beta
  link in the README now that Nostr VPN is eligible for distribution.

### Changed

- Bumped to FIPS 0.3.80/0.3.55 for the latest FIPS dataplane cleanup and
  endpoint packet-buffer API.
- User-facing peer/admin public keys in config continue to load from legacy hex
  values and save back as npubs.
- Derived mesh tunnel IPs recompute when the device identity changes, while
  custom non-mesh tunnel IPs are preserved.

### Fixed

- `nvpn doctor` now reports a critical issue when this device identity is not in
  the active network roster and no join request is pending.

## 4.0.87 - 2026-06-22

### Fixed

- Refreshed stale embedded FIPS private-mesh direct paths using tunnel data
  freshness when available, so fresh control traffic does not hide a dead
  payload path and fresh payload data avoids unnecessary FIPS endpoint churn.

## 4.0.86 - 2026-06-22

### Fixed

- Bumped to FIPS 0.3.77/0.3.52 for direct-path staleness based on
  authenticated receive evidence, local route-failure payload recovery, and
  refreshed endpoint adverts after route-unreachable sends.
- Hardened the FIPS roaming Docker release gate so direct UDP drops and
  route-unreachable flaps keep continuous payload flowing through fallback and
  recover direct paths within a bounded window.

## 4.0.85 - 2026-06-22

### Fixed

- Preserved daemon-sourced FIPS reachability fields in `nvpn status --json`, so
  GUI/device lists no longer collapse active roster peers to offline.
- Stopped forcing macOS connected UDP on by default; macOS now inherits FIPS'
  default-off behavior unless explicitly enabled.
- Refreshed embedded FIPS private-mesh paths in place after link changes instead
  of restarting the FIPS endpoint, reducing churn during route or endpoint
  refreshes.
- Bumped to FIPS 0.3.76/0.3.51 for fresh endpoint peer liveness, preventing
  stale receive counters from keeping dead mobile/NAT paths marked online, and
  for stale worker-open completion classification during FSP session churn.

## 4.0.83 - 2026-06-21

### Changed

- The workspace now depends on the published FIPS 0.3.75/0.3.50 crates,
  carrying the direct-path re-probe and direct-payload freshness fixes used by
  the latest private-mesh recovery testing.
- FIPS/Nostr discovery now defaults to configured roster peers only; open
  non-roster transit remains available as an explicit setting or env override.
- FIPS public configured endpoints are treated as ordinary roster hints instead
  of authoritative paths; public relay advertising remains opt-in.
- macOS FIPS private-mesh pacing defaults are now expressed as a bounded bulk
  admission policy derived from MTU and socket-buffer relationships instead of
  standalone emergency constants. The effective queue and UDP buffer defaults
  remain the 4.0.82 release values.
- FIPS private-mesh sender fairness now yields from actual bulk queue pressure
  instead of macOS-only fixed send-turn constants, matching the WireGuard-style
  bounded queue/backpressure model more closely.
- Release-gate local-FIPS coverage now checks that traversal/recent-endpoint
  paths keep their mobile-safe liveness floor instead of falling back to the 5s
  local-route-failure timeout.
- Release-gate local-FIPS coverage now rejects configured-only Nostr traversal
  regressions where non-roster handoffs are adopted before roster admission.
- FIPS private-mesh maintenance now probes stale peers on the slower discovery
  cadence and caps peer pings per heartbeat to avoid synchronized control bursts
  from stale/offline roster members.

### Fixed

- Private-mesh transfers no longer stay pinned to stale fallback routes after
  authenticated direct endpoint payload traffic has returned, reducing slow
  reverse transfers after network changes.

## 4.0.82 - 2026-06-20

### Fixed

- Windows default builds no longer crash at startup when hidden paid-route view
  markup is loaded. Paid-route buy/sell/wallet UI remains hidden unless the
  default-off paid-exit feature and runtime support are enabled.

## 4.0.81 - 2026-06-20

### Changed

- The workspace now depends on the published FIPS 0.3.73/0.3.48 crates, carrying
  the direct-path freshness, direct-probe routing, degraded static-direct route,
  and endpoint-priority scheduling fixes used by the post-4.0.80 stabilization
  runs.
- Cashu paid-exit buy/sell internet work remains opt-in behind the default-off
  `paid-exit` feature. Default builds keep Cashu out of the normal daemon
  dependency graph and hide unsupported Buy Internet, Share Internet, and Wallet
  UI instead of showing placeholder "not available" pages.
- Retired stale dataplane benchmark knobs for FIPS source-affine/FSP worker-open
  placement, FSP completion width, Linux bulk UDP pacing, and macOS ordered
  sender experiments. Current FIPS defaults now own those shapes directly, and
  Docker benchmark harnesses reject the old env names instead of silently
  recording misleading evidence.

### Fixed

- Default FIPS private-mesh builds now keep the connected-UDP fast path opt-in
  after live roster testing showed it could cause burst packet loss on otherwise
  clean LAN paths. `node.connected_udp.enabled = true` and `FIPS_CONNECTED_UDP=1`
  remain available for explicit A/B runs.
- FIPS path refresh now targets stale and pending direct-probe paths without
  churning fresh routes, and nvpn uses FIPS data-path freshness plus outbound
  route status to avoid keeping degraded static/private hints on the hot path.
- Release-gate coverage now includes the degraded static FIPS routing
  regression so roster/static-route recovery stays protected.

## 4.0.80 - 2026-06-19

### Changed

- The workspace now depends on the published FIPS 0.3.67/0.3.42 crates, which
  carry the stale-path and raw-UDP pacing fixes plus a final receive-loop
  scheduling reduction that bounds non-packet, fallback, and side-turn work
  between dataplane receives under LAN load.
- Release-gate local-FIPS runs and the fast FIPS safety suite now include the
  overlay/update-peers regression filters that cover this stale-path class.
- The optional host-pair loaded-latency release gate now clamps sub-second ping
  intervals on non-root macOS and exposes an explicit
  `NVPN_RELEASE_GATE_HOST_PAIR_LOADED_MAX_STALL_INTERVALS` threshold for live
  Wi-Fi/LAN runs.

### Fixed

- Active direct-path refreshes can now reach FIPS path-candidate reclaim logic
  even when the per-peer race budget is already full, so better configured
  paths are not blocked behind lower-priority in-flight attempts.
- macOS private-mesh LAN transfers no longer require launchd pacing overrides
  to keep loaded-latency stable during sustained TCP traffic.

## 4.0.79 - 2026-06-19

### Changed

- The workspace now depends on the published FIPS 0.3.64/0.3.39 crates, which
  skip slow RX-loop maintenance while queued dataplane work is waiting and
  shorten decrypt-worker bulk batches to bound priority stalls under LAN load.
- Release-gate platform and desktop smoke checks now have bounded timeouts so
  Docker perf evidence cannot be hidden behind a later hung smoke test.

## 4.0.78 - 2026-06-19

### Changed

- The release gate can now run an optional host-pair loaded-latency check that
  keeps ping running while TCP throughput probes run, catching tunnel stalls,
  packet loss, and low-throughput iperf intervals in configured real-device
  environments without committing local host details.
- macOS FIPS private-mesh sending now sequences endpoint flows independently
  on the ordered Darwin sender path, so one bulk TCP flow cannot block
  latency-sensitive tunnel traffic to the same peer.
- The workspace now depends on the published FIPS 0.3.63/0.3.38 crates that
  contain the direct-path liveness and decrypt-worker priority-lane fixes.
- Embedded FIPS endpoints now declare a silent direct path stale after 20s
  instead of 30s, shortening real blackhole failover while keeping the
  existing 15s traversal-path floor and 5s fast local-failure path.

### Fixed

- FIPS Nostr discovery GUI toggles now restart the embedded endpoint so live
  relay subscriptions are closed immediately instead of waiting for a daemon
  process restart.
- Configured-only FIPS discovery no longer seeds built-in bootstrap or recent
  non-roster transit peers, keeping low-power nodes out of public transit retry
  churn while preserving roster/static hints.
- Open FIPS discovery now caps bootstrap/transit seeds before applying the open
  discovery admission budget, preventing large learned bootstrap lists from
  exhausting fresh-discovery headroom and churning on ambient peers.
- The release gate now honors `NVPN_FIPS_REPO_PATH` for its blocking Cargo
  clippy/test steps, so local FIPS API changes are tested with the same patch
  set used for daemon builds.
- The Docker FIPS perf gate now fails on low-throughput iperf intervals instead
  of only checking whole-run averages.
- macOS app windows refresh daemon state when the app starts or is shown again,
  preventing stale one-device roster views after daemon/config changes.
- Active direct-path refreshes without concrete direct candidates now use a
  cooldown instead of tight retry churn.

## 4.0.77 - 2026-06-15

### Changed

- macOS FIPS private-mesh bulk traffic now uses a smaller queue and UDP send
  buffer window to keep endpoint latency bounded while preserving the measured
  coalescing behavior.

### Fixed

- FIPS participant liveness now prefers recent authenticated participant
  traffic over connected endpoint-link snapshots, so stale peers are reported
  accurately instead of appearing healthy through a lingering transport link.
- The daemon now restarts the embedded FIPS private mesh, with cooldown, when
  participant traffic stops while endpoint links remain connected, helping
  recover stale participant paths automatically.

## 4.0.76 - 2026-06-15

### Changed

- Linux FIPS private-mesh dataplane now includes the direct endpoint-payload
  send path, opt-in vnet TUN fast path guardrails, and wider Linux receive
  drains used by the latest latency benchmark work.
- Docker FIPS perf and soak harnesses now capture richer benchmark provenance,
  trace mismatches, bulk-container pressure, receive drops, and bounded iperf
  probe windows.

### Fixed

- FIPS TUN-to-mesh queuing now preserves priority progress under bulk load by
  classifying liveness/control packets separately from bulk tunnel traffic and
  accounting queued bulk capacity by packet.
- Linux FIPS throughput/latency experiments now use tuned TUN queue depth and
  mesh burst behavior without undoing the macOS bounded queue/coalescing
  safeguards from 4.0.75.

## 4.0.75 - 2026-06-15

### Changed

- The release gate now includes the host-pair latency check when the required
  SSH environment is configured.
- FIPS now uses `fips-core` 0.3.60 and `fips-endpoint` 0.3.35.

### Fixed

- The macOS FIPS private-mesh send path now includes the bounded queue latency
  fix in tagged release artifacts.
- The embedded FIPS receive loop now keeps idle slow-maintenance slices below
  the release-gate priority wait budget.
- The FIPS Docker perf gate now checks priority wait latency against the
  selected load-window telemetry instead of idle/restart peak samples.

## 4.0.74 - 2026-06-14

### Changed

- Unix FIPS TUN-to-mesh queuing now defaults to a larger bounded bulk budget
  and exposes an explicit environment override for controlled A/B trials.
- FIPS now uses `fips-core` 0.3.58 and `fips-endpoint` 0.3.33.

### Fixed

- macOS FIPS bulk TUN traffic is coalesced briefly before mesh send while
  keeping liveness/control packets priority-biased, improving sustained
  private-mesh throughput without delaying priority traffic.

## 4.0.73 - 2026-06-12

### Changed

- FIPS now uses `fips-core` 0.3.56 and `fips-endpoint` 0.3.32.
- Large Rust modules were split into focused submodules so every Rust source
  file is at or below the 1000-line maintenance cap.

### Fixed

- The embedded FIPS dataplane now includes the latest upstream control-plane
  progress and dataplane reliability fixes while preserving peer/session
  continuity under queue pressure.
- Windows builds now pick up the FIPS patch that keeps shared dataplane worker
  state available on non-Unix targets while leaving Unix raw-socket batching
  platform-gated.
- Release Docker and Linux dev builds no longer require a sibling hashtree
  checkout now that the updater dependency is pinned to published crates.

## 4.0.72 - 2026-06-07

### Changed

- FIPS now uses `fips-core` 0.3.54 and `fips-endpoint` 0.3.30.

### Fixed

- FIPS receive-loop handling now stays responsive under bulk endpoint egress
  by keeping priority endpoint commands ahead of bulk tunnel traffic and
  treating saturated bulk worker queues as network backpressure.
- The embedded mesh receive path now cooperates with Tokio scheduling after
  forwarding packets to TUN so hot inbound streams do not starve timers or
  control work.

## 4.0.71 - 2026-06-07

### Changed

- FIPS now uses `fips-core` 0.3.53 and `fips-endpoint` 0.3.29.

### Fixed

- FIPS now includes the latest upstream triage fixes for authenticated FMP
  K-bit rekey promotion, bounded FMP msg1 retransmission, dual Nostr
  traversal election, TCP/Tor inbound accounting, overlapping Bloom mesh-size
  estimates, and selected poisoned mutex/logging panic hardening.

## 4.0.70 - 2026-06-07

### Changed

- FIPS now uses `fips-core` 0.3.52 and `fips-endpoint` 0.3.28.
- The FIPS perf regression gate now stresses encrypt-worker queue pressure
  while checking throughput and latency under bulk TCP load.
- The Docker FIPS perf gate now uses the pinned published FIPS crates by
  default, retries empty iperf samples, and gives the synthetic worker-pressure
  ping check a CI-sized during-load loss budget while still checking post-load
  recovery tightly.

### Fixed

- FIPS TCP bulk endpoint-data traffic no longer starves queued session
  handshakes or mesh control packets under sustained throughput.
- The macOS test-daemon installer now resolves Cargo's configured output path
  before swapping binaries.

## 4.0.69 - 2026-06-06

### Changed

- FIPS now uses `fips-core` 0.3.51 and `fips-endpoint` 0.3.27.
- Added the `osiris` public FIPS bootstrap peer as a second built-in bootstrap
  route alongside `lnvps`.
- Release-gate smoke testing now launches the desktop GUI on Linux, macOS, and
  Windows so app startup regressions fail before tagging.
- Windows VM release helpers now sync source through Git SSH remotes instead
  of tar streams.

### Fixed

- FIPS direct-path routing and macOS direct sends now use the latest upstream
  throughput-stability fixes.
- The Windows app no longer crashes during startup when WPF initializes the
  read-only public FIPS address field.

## 4.0.68 - 2026-06-06

### Changed

- FIPS now uses `fips-core` 0.3.49 and `fips-endpoint` 0.3.25.
- The release gate now includes a FIPS dataplane regression check that keeps
  TCP throughput above a floor and verifies ping latency during and after bulk
  TCP load.

### Fixed

- Mesh MTU settings from app config now use the same resolver as environment
  overrides, so configured LAN MTU profiles are honored without launchd
  environment edits.
- Operator-configured static FIPS endpoint hints now stay unstamped even when
  the same socket also appears in recent endpoint discovery, keeping explicit
  LAN paths preferred while direct probing continues.
- Runtime FIPS peer refreshes now detect endpoint hint freshness and priority
  changes, not just address-string changes.
- FIPS TCP endpoint-data packets now backpressure instead of being dropped by
  the encrypt worker under bulk-send pressure, fixing the GitHub CI session
  initiation and Windows endpoint-data regressions.

## 4.0.67 - 2026-06-05

### Changed

- FIPS now uses `fips-core` 0.3.39 and `fips-endpoint` 0.3.24.

### Fixed

- FIPS fallback routing now keeps established packets flowing when a direct
  UDP path is marked link-dead, while direct probing continues in the
  background.
- Transit nodes no longer bounce learned fallback routes back to the previous
  hop, preventing mesh loops that could exhaust packet TTL after direct-path
  loss.
- Fresh fallback discovery now warms established sessions immediately and keeps
  coordinate-carrying warmup packets out of discardable bulk queues.

## 4.0.66 - 2026-06-05

### Changed

- FIPS now uses `fips-core` 0.3.38 and `fips-endpoint` 0.3.24.

### Fixed

- Direct-path failures no longer reinstall a stale UDP fast path after
  link-dead. Mesh can carry traffic as fallback while direct UDP keeps
  probing and upgrades back when the path recovers.

## 4.0.65 - 2026-06-05

### Changed

- FIPS now uses `fips-core` 0.3.37 and `fips-endpoint` 0.3.24.

### Fixed

- Direct UDP liveness failures now make only the dead link stale. Stale direct
  links remain probe targets, but FIPS no longer selects them for payload or
  lookup routing, so packets rediscover and use fallback instead of
  blackholing on the old UDP path.
- Nostr/STUN-discovered UDP paths now fall back after a short liveness window
  when they go quiet, even if they previously carried traffic. Mesh stays a
  fallback transport while direct UDP keeps probing.
- Fresh fallback discovery now flushes queued traffic through existing
  sessions, so fallback starts carrying packets immediately after direct UDP is
  marked stale.

## 4.0.62 - 2026-06-05

### Changed

- FIPS now uses `fips-core` 0.3.33 and `fips-endpoint` 0.3.24.

### Fixed

- Link-dead direct UDP paths now stay as stale/probeable candidates instead
  of making the FIPS peer non-sendable, so nvpn traffic can keep flowing over
  mesh fallback while direct probes and late authenticated packets revive the
  path.

## 4.0.61 - 2026-06-05

### Changed

- FIPS now uses `fips-core` 0.3.32 and `fips-endpoint` 0.3.24.

### Fixed

- Healthy-but-slow direct UDP paths no longer hide clearly better mesh
  fallback routes; fallback can carry packets while direct probing continues.
- Moderate direct-path loss now demotes traffic to fallback sooner instead of
  waiting for severe loss or a link-dead timeout.
- Stale macOS service plists with `FIPS_MACOS_CONNECTED_UDP=0` no longer
  disable FIPS connected UDP.

## 4.0.60 - 2026-06-05

### Changed

- FIPS now uses `fips-core` 0.3.31 and `fips-endpoint` 0.3.24.

### Fixed

- Repeated direct UDP drops no longer let a reconnecting static path look
  "fresh" enough to suppress direct re-probing, so mesh remains fallback
  transport instead of becoming a sticky demotion after hotspot flaps.

## 4.0.59 - 2026-06-05

### Changed

- FIPS now uses `fips-core` 0.3.30 and `fips-endpoint` 0.3.23.

### Fixed

- Direct-path retry maintenance now re-probes the last observed UDP endpoint
  after link-dead, while mesh/relay stays only as fallback traffic transport.
  This prevents transient hotspot liveness failures from pinning peers to
  `runtime_endpoint: "fips"`.

## 4.0.58 - 2026-06-04

### Changed

- FIPS now uses `fips-core` 0.3.29 and `fips-endpoint` 0.3.22.

### Fixed

- FIPS link-dead direct paths now immediately refresh fallback routing through
  live transit peers while direct UDP reprobes continue in the background.
- Daemon and mobile status now keep retry-only direct probe state separate from
  authenticated direct-link connectivity, so `runtime_endpoint: "fips"` can
  accurately mean fallback transport is carrying traffic while direct probing
  is still active.
- The release gate now includes a three-node roaming Docker scenario that
  drops, restores, and drops direct Alice/Bob UDP again to catch sticky
  fallback demotion regressions.

## 4.0.57 - 2026-06-03

### Changed

- FIPS status now distinguishes fallback mesh/relay transport from background
  direct UDP probing, including native app state and `nvpn status --json`.

### Fixed

- FIPS direct paths now behave like retryable candidates instead of sticky
  privileged routes: link-dead UDP paths schedule quick reprobes, fresh
  discovered candidates can outrank stale static hints, and fallback mesh
  keeps traffic flowing without suppressing direct upgrades.
- Mobile-hotspot NAT flaps no longer turn one or two direct liveness failures
  into long Nostr traversal cooldowns that pin a peer to mesh.

## 4.0.56 - 2026-06-03

### Fixed

- FIPS static endpoint hints now ignore stale private, CGNAT, and link-local
  addresses unless they match the current local underlay subnet, preventing old
  LAN addresses from blocking fresh traversal candidates.
- FIPS direct-path retries are less punitive on mobile-hotspot NAT flaps: nvpn
  now probes direct paths more frequently and avoids long Nostr traversal
  cooldowns after only one or two transient liveness failures.

## 4.0.55 - 2026-06-03

### Fixed

- Umbrel first-run configs now select the initial admin network and seed the
  local `.nvpn` name, keeping device invites and the self device visible while
  the VPN daemon is paused.

## 4.0.54 - 2026-06-02

### Changed

- FIPS now uses `fips-core` 0.3.27 and `fips-endpoint` 0.3.20.

### Fixed

- macOS test-daemon installs now resolve Cargo's real target directory and
  verify the built `nvpn` version before installing, preventing stale
  `target/release/nvpn` binaries from being copied when a custom Cargo target
  dir is configured.
- Daemon network-refresh status now returns to `VPN on` after recovery instead
  of leaving the GUI in a stale refresh state.
- Daemon startup failures now write an explicit failure status instead of
  leaving the previous projected `Turning VPN on` state visible.
- FIPS bulk send saturation no longer blocks link liveness/control handling,
  reducing false link-dead drops during high-rate traffic such as Screen
  Sharing.
- FIPS direct-path traversal failures now back off stale recent endpoint paths
  after link-dead timeouts, so silent UDP upgrades stop repeatedly interrupting
  otherwise reachable peers.
- Recently advertised FIPS endpoint paths now use a bounded liveness timeout,
  reducing direct-path failover delay without shortening normal relayed links.

## 4.0.52 - 2026-06-01

### Changed

- FIPS now uses `fips-core` 0.3.24 and `fips-endpoint` 0.3.18.

### Fixed

- FIPS rekey responders now wait for the peer's authenticated K-bit flip
  instead of time-cutting over on their own maintenance tick, avoiding
  split-session direct links after rekey churn.

## 4.0.51 - 2026-06-01

### Changed

- FIPS now uses `fips-core` 0.3.23 and `fips-endpoint` 0.3.17, adding
  roster-scoped NAT traversal signaling over established FIPS mesh sessions,
  bounded active-peer direct-refresh retries, and broader STUN target probing.
- Local release artifact builds now use locked Cargo resolution and
  deterministic build environment defaults across macOS, Linux, Windows, and
  CLI archives.

### Fixed

- FIPS roster peers that are already reachable via mesh now keep a backed-off
  direct path refresh alive, so stale static/private endpoint hints no longer
  pin peers on sluggish relayed or via-mesh paths indefinitely.
- Recent FIPS endpoint hints are capped and pruned before they become
  non-roster discovery seeds, keeping open-discovery peer fan-out bounded.

## 4.0.50 - 2026-05-30

### Changed

- Android now follows the system dark/light theme.
- Mobile release tooling now has local environment-file support for physical
  device smoke tests without committing device IDs or signing details.

### Fixed

- Android and iOS mobile tunnels now keep MagicDNS on a local in-tunnel
  responder address instead of treating the resolver as a remote nvpn peer.
- Android and iOS WireGuard exit-node mode now starts without waiting for the
  upstream handshake, letting Android protect the WireGuard UDP socket before
  default-route traffic can trap it in the VPN.
- Mobile WireGuard and FIPS exit traffic now finalizes IPv4 TCP/UDP checksums
  after address rewrites, fixing packet loss through exit nodes.
- iOS now installs full-tunnel packet settings for selected FIPS exit nodes and
  handles MagicDNS plus public DNS failover correctly on iOS 26.
- Active-network invite generation now requires the local device to be an
  admin, so non-admin devices cannot mint invites.
- Mobile app rows now keep full npubs in device detail views and avoid
  hyphenating/wrapping npubs.

## 4.0.49 - 2026-05-30

### Changed

- Android-only Zapstore build, superseded by 4.0.50 so Android and TestFlight
  use the same fresh mobile release number.

## 4.0.48 - 2026-05-28

### Changed

- Android now restores the VPN from OS Always-on VPN and boot/startup restore
  paths using the persisted tunnel config, so a previously requested tunnel can
  come back without an interactive app launch.
- Android VPN startup now refreshes the active underlying network and DNS
  forwarders before handing config to the mobile tunnel, and the app surfaces
  current always-on/lockdown state more directly.
- The CLI and desktop updater path now uses the secure hashtree/Nostr/Blossom
  update source by default, with improved check/download output and Windows
  update handling.
- Android and macOS launcher icons have more padding so they render less
  tightly cropped across launchers and system surfaces.

### Fixed

- Mobile route exports now preserve stable peer identifiers and names through
  the app-core FFI, fixing route and participant display in native shells.
- Android join-request and lockdown status messages now stay accurate across UI
  refreshes and service state changes.
- Mobile tunnels now build MagicDNS and peer routing state more reliably,
  including DNS forwarder selection from Android's active underlying network.
- iOS now passes the packet tunnel its full launch config through per-start
  provider options instead of making the extension read the app container,
  fixing scanned-invite join requests on physical iPhones.
- Manual mobile network entry now seeds the admin as the peer to contact without
  creating a join request.

## 4.0.47 - 2026-05-27

### Changed

- FIPS bootstrap routing now defaults on and uses the `lnvps` public bootstrap
  node as the sole built-in peer, with IPv4 and IPv6 UDP plus TCP fallback
  hints.
- FIPS now uses `fips-core` 0.3.22, which fixes connected UDP `POLLERR` drain
  spins and adds fair encrypted-send admission for saturated bootstrap/server
  nodes.

### Fixed

- Persisting `fips_bootstrap_enabled = false` now keeps bootstrap disabled
  across config reloads, so isolated tests and explicitly opted-out users do not
  silently re-enable the new default.

## 4.0.46 - 2026-05-27

### Changed

- FIPS bootstrap routing now defaults on and uses the `lnvps` public bootstrap
  node as the sole built-in peer, with IPv4 and IPv6 UDP plus TCP fallback
  hints.
- FIPS now uses `fips-core` 0.3.22, which fixes connected UDP `POLLERR` drain
  spins and adds fair encrypted-send admission for saturated bootstrap/server
  nodes.

## 4.0.45 - 2026-05-27

### Fixed

- macOS release builds now compile the Add Network join-request section with
  an explicit SwiftUI return, unblocking local htree release artifacts.

## 4.0.44 - 2026-05-27

### Fixed

- FIPS now uses `fips-core` 0.3.21, porting upstream admission and tree
  stability fixes for saturated meshes.
- Add Network now keeps a local "Join request sent" status visible after
  requesting access until the Add Network surface closes.

## 4.0.43 - 2026-05-27

### Changed

- Settings now label relay-based FIPS discovery as "Find peers over Nostr
  relays", and bootstrap servers default off for new configs.
- Release checks now include a Rust dependency audit.

### Fixed

- FIPS now uses `fips-core` 0.3.20, which caps connected UDP file descriptor
  use, fixes connected UDP drain shutdown, and keeps YAML config overlays from
  replacing unrelated `node` defaults.
- Admin roster events are now signed with the current Nostr SDK APIs and
  verified before being accepted.
- The daemon now reports "Network route refresh failed" for route refresh
  failures instead of the previous "return" typo.
- The web settings save button is scoped to public FIPS routing changes instead
  of appearing as an unrelated page footer action.

## 4.0.42 - 2026-05-26

### Changed

- Public FIPS routing settings now include a short explanation and Learn FIPS
  link, and are grouped after the core FIPS peer settings on web, macOS, Linux,
  and Windows.

### Fixed

- iOS now preserves pasted WireGuard upstream configs while background app
  state refreshes are running, instead of replacing the unsaved draft with the
  last saved config.

## 4.0.41 - 2026-05-26

### Changed

- Settings are split consistently across platforms so device, general, FIPS,
  and public FIPS routing controls are not grouped under "This Device".
- Public FIPS routing settings now show the device's `npub.fips` address and
  label the inbound TCP port field as public `.fips` routing.

### Fixed

- Joining by invite on a fresh Umbrel install now uses the existing empty
  starter network instead of creating another "Network 1" entry, and selects
  the joined network after import.
- iOS TestFlight release archives now use pinned App Store profiles and
  Transporter HTTP uploads, matching the currently available App Store profile
  entitlements.

## 4.0.40 - 2026-05-24

### Added

- Admin-signed roster sync now travels over FIPS control events so members can
  converge on the latest admin roster without a public Nostr relay publish.

### Changed

- `.fips` host routing now defaults off and remains an explicit opt-in.
- Local htree release publishing now defaults to draft mode; use the explicit
  final/promote path to repoint `latest`.
- macOS `just run` no longer invalidates the normal Cargo cache when building
  the app-core framework and bundled CLI.

### Fixed

- Config secrets are migrated out of plaintext config files on startup.
- App update checks on macOS, Linux, Windows, Android, and the CLI now check
  the htree release manifest before falling back to GitHub, keeping htree-first
  releases discoverable without waiting on GitHub.
- FIPS endpoint state now restarts or refreshes after sleep/wake, network
  changes, endpoint changes, and macOS underlay route repairs so peers
  reconnect cleanly after a machine wakes.
- macOS desktop refreshes now avoid overlapping background service status
  checks and fall back to the live daemon version while the service is running,
  reducing UI churn around service-update prompts.
- macOS config secrets now use private per-config sidecar files instead of the
  System Keychain, avoiding repeated administrator prompts.
- Mobile tunnel launch configs redact persisted secret markers before crossing
  the platform boundary.

## 4.0.39 - 2026-05-22

### Added

- Built-in public FIPS bootstrap nodes, dialed as fallback transit so peers can
  still reach each other when direct NAT traversal and relays fail. They seed a
  single editable peer list in config (shared with any custom transit peers);
  the web settings show it with inline editing and a "reset to defaults" button,
  and every platform has a "Use bootstrap servers" master toggle (default on).
- Embedded `.fips` host tunnel: `.fips` hosts now route through a fips-core TUN
  with the fips-core host firewall instead of the legacy path.
- Import WireGuard configuration files directly from the apps on every platform.
- Manual network join in the web UI for joining a network by id without an
  invite, with full device id and grouped network id display.
- Outbound TCP transport so bootstrap/transit peers advertised on `tcp:443` can
  be reached on networks that block UDP outright. Peer addresses can be
  transport-tagged (`tcp:` / `udp:`), while bare addresses remain UDP.

### Changed

- New "Find peers over relays" settings toggle (default on) to disable
  finding/advertising FIPS peers over Nostr relays; static, bootstrap, and LAN
  connectivity keep working when it is off. Available on web, macOS, iOS,
  Android, Windows, and Linux, and via `nvpn set --fips-nostr-discovery-enabled`
  / `--fips-bootstrap-enabled`.
- Linux desktop GUI reaches settings parity with macOS, supports close-to-tray,
  and now launches hidden on startup.
- Diagnostics surface per-peer FIPS stats on both desktop and mobile.
- Invite QR codes are larger and rendered as SVG for sharper scanning, and
  invite secrets and group network ids now rotate.
- Learned non-roster FIPS peers are now kept as fallback transit peers, so
  authenticated overlay neighbors discovered in previous sessions can help
  route lookups after restart.
- Docker e2e images now build against the published FIPS crates by default;
  set `NVPN_PATCH_LOCAL_FIPS=1` with `NVPN_FIPS_REPO_PATH` to test a local FIPS
  checkout.
- Device lists hide the search field when short, normal button colors are
  muted, and macOS device/exit-node/rename fields no longer rebuild the whole
  root view on each keystroke, keeping text input responsive on large rosters.
- StartOS packaging refresh: web UI binds off the VPN interface, ships the
  Nostr VPN icon, and is prepared for app submission; Umbrel app submission
  packaging and updated app-store port.

### Fixed

- CLI invite import now preserves the invite secret so FIPS join requests sent
  from imported invites are accepted by the admin.
- Docker FIPS e2e scripts with static local topologies now disable public
  relay/bootstrap discovery so outside peers cannot perturb deterministic
  continuity checks.
- Linux musl CLI release builds no longer depend on Cargo pre-extracting the
  `rustables` registry source before the nftables header workaround is applied.
- macOS release builds include regenerated app-core bindings and project
  versions for the new FIPS discovery/bootstrap settings.
- Recent FIPS peer caches preserve learned TCP transport tags while continuing
  to accept old bare UDP endpoint entries.
- FIPS peer discovery settings and roster propagation for stale peers.
- Windows exit-node list build.

## 4.0.38 - 2026-05-20

### Fixed

- Updated the embedded FIPS endpoint stack to `fips-endpoint` 0.3.15 so
  outbound-only stale sessions are expired and re-handshaken when peers stop
  returning authenticated FSP frames, preventing direct LAN links from staying
  wedged until daemon restart.

## 4.0.37 - 2026-05-19

### Changed

- Daemon now persists runtime state at most once every 5 seconds and refreshes
  recent-peer summaries on the mesh refresh cadence instead of on every 1-second
  status tick, cutting redundant disk writes and FIPS snapshot work on idle
  devices. Persistence failures are now surfaced via stderr instead of silently
  swallowed.
- `nostr-vpn-cli` now treats Nostr relay list changes as a configuration delta
  for the FIPS private tunnel runtime, so relay edits hot-apply through the
  existing reconfigure path instead of waiting for the next process restart.

## 4.0.36 - 2026-05-18

### Changed

- Admins can now rename their own device from the native and web device UIs.

### Fixed

- Devices now drop a network locally when an admin removes that device from the
  roster, so a removed member does not keep stale local network state.

## 4.0.35 - 2026-05-18

### Fixed

- Native apps now accept daemon relay status entries that omit UI-only enabled
  flags, fixing `nvpn status --json` parse failures when FIPS reports live relay
  connectivity.
- Native apps now read the daemon's snake_case `last_fips_seen_at` timestamp so
  live FIPS peer presence updates correctly.

## 4.0.34 - 2026-05-18

### Added

- Default relay settings now include `wss://temp.iris.to` from FIPS discovery
  defaults.

### Changed

- Relay settings now use per-relay add, enable, disable, and delete controls
  instead of a multiline relay editor across native app surfaces.

### Fixed

- The macOS app now accepts the daemon's snake_case mesh timestamp fields when
  parsing `nvpn status --json`, so live status refreshes and relay dots keep
  updating after service upgrades.

## 4.0.33 - 2026-05-18

### Added

- Relay settings are now editable across desktop, mobile, and web surfaces,
  with live gray/green relay status indicators fed by the FIPS endpoint.

### Changed

- Updated the embedded FIPS endpoint stack to `fips-endpoint` 0.3.13, which
  hot-applies Nostr relay changes without rebuilding the running endpoint.
- iOS TestFlight exports now honor `NVPN_IOS_INTERNAL_ONLY=false` so public
  beta uploads are not accidentally marked internal-only.

## 4.0.32 - 2026-05-18

### Changed

- Updated the embedded FIPS endpoint stack to `fips-endpoint` 0.3.12.

## 4.0.31 - 2026-05-18

### Changed

- FIPS peers without a direct endpoint are now labeled as `via mesh` across the
  native and web device UIs.
- Incoming join requests are now visible from the Add Device flow as well as
  the Devices list, with a Devices tab attention dot when requests are waiting.

### Fixed

- Routed FIPS peers now retain control-channel RTT on desktop and mobile, so
  cellular/mesh paths can show live latency instead of falling back to only
  `seen N seconds ago`.
- Importing an invite for a different network now creates and activates that
  network instead of mutating an existing named active network.
- FIPS endpoint hints now ignore placeholder, documentation, localhost, and
  public-key-shaped values before saving or advertising them.

## 4.0.30 - 2026-05-18

### Fixed

- Invites now carry the inviter's current FIPS endpoint hint and import stores
  that hint for the admin peer, so join requests do not depend only on stale
  overlay endpoint discovery.
- Placeholder/documentation endpoints such as `198.51.100.10:51820` now trigger
  endpoint autoconfiguration instead of being advertised as real peer addresses.

## 4.0.29 - 2026-05-17

### Changed

- MagicDNS no longer invents aliases for unnamed roster members;
  devices can be in a roster without an `.nvpn` name until an admin names them.
- Pending join requests seed only temporary local `self.nvpn` and `admin.nvpn`
  names until the accepted shared roster provides real aliases.
- Pending FIPS join requests now use the same 10-second retry cadence on
  desktop and mobile.

### Fixed

- Admins can rename their own device from every native network UI.
- Enabling join requests from the native app now starts the background FIPS
  listener when needed, so admins can receive requests while the app is open.
- FIPS join-request senders on desktop and mobile keep endpoint hints for
  admin-only control peers without treating them as accepted data-plane peers,
  and the Docker e2e no longer pre-seeds admin config by editing TOML.
- Mobile join-request listeners and pending senders now enable FIPS discovery
  even before any accepted roster peer exists.
- Mobile join requests now have an app-core integration test that sends the
  request through real FIPS endpoints and records it on the admin side.

## 4.0.28 - 2026-05-17

### Changed

- FIPS Docker e2e runs now use deterministic configured-only Nostr discovery,
  keeping the test meshes off the public relay overlay while preserving open
  discovery as the runtime default.
- Docker e2e compose files can use `NVPN_FIPS_REPO_PATH` for the local FIPS
  checkout path.
- The release gate now includes a Docker e2e check for invite-based FIPS join
  requests from a non-roster requester to an admin listener.

### Fixed

- Admin-signed shared rosters now apply MagicDNS aliases for the local device
  itself, so an admin-set name such as `iphone.nvpn` replaces an older local
  fallback.
- Mobile admins now persist inbound FIPS join requests from unknown requesters,
  and native app state exposes pending requests for every UI shell.
- The release gate now runs the routed FIPS and NAT safe-MTU Docker e2e tests
  again instead of printing a known-broken skip.

## 4.0.27 - 2026-05-17

### Added

- iOS debug builds now support fixture mode for App Store screenshots,
  using non-real mesh, device, exit-node, and WireGuard data.
- Added App Store Connect draft tooling that can update metadata, attach
  the release build, and upload iPhone/iPad screenshot sets.
- Added repeatable iPhone and iPad simulator screenshot capture for the
  required App Store display classes.
- Umbrel now has a responsive web control panel path with app-core API
  routing and Docker e2e coverage for the VPN toggle flow.

### Changed

- iOS mobile flows now use the manual add-network path and a quieter VPN
  disclosure notice.
- Native and web device lists show calmer, more consistent peer status
  labels, with MagicDNS names treated as authoritative when present.
- Exit-node leak protection is enabled by default.

### Fixed

- iOS now persists the generated Nostr identity when first-run device-name
  seeding creates a partial config file, avoiding a fresh install that shows no
  saved identity until another config write happens.
- Android peer presence and GUI autostart now recover correctly.
- Mobile FIPS reachability state is reported correctly.
- The final saved network can be deleted.

## 4.0.26 - 2026-05-17

### Added

- iOS now bundles a privacy manifest declaring the app-local
  UserDefaults, file metadata, and timer API reasons used by the app and
  packet-tunnel extension.
- TestFlight tooling can now expire a specific uploaded build before
  submitting a replacement public beta.

## 4.0.25 - 2026-05-17

### Added

- iOS now shows a VPN data-use disclosure before the first tunnel
  activation, explaining private-network data use, user-selected
  relays/exit nodes, and the no sale/tracking/third-party disclosure
  policy.

### Changed

- Public TestFlight review metadata and the privacy policy now describe
  Nostr VPN as a private VPN and generic WireGuard exit-node utility,
  not a public VPN, anonymity, stealth, or consumer proxy service.

### Fixed

- FIPS peer config initializers compile against the current local FIPS
  discovery fallback transit setting.

## 4.0.24 - 2026-05-17

### Added

- Join requests can now be rejected from Android, iOS, Linux, macOS,
  Windows, and the web UI, with app-core support for clearing stale
  pending requests.
- Saved inactive networks now expose contextual activation controls in
  the Devices view: compact desktop controls on macOS and a full-width
  `Activate Network` action on iOS, while the header network picker
  remains a view switcher.
- Added a reusable Linux musl daemon build helper and updated the ARMv6
  helper so Raspberry Pi builds can apply a local FIPS patch cleanly.

### Fixed

- FIPS event refreshes no longer starve behind unrelated public discovery
  events, keeping configured-peer refresh work moving under noisy overlay
  conditions.
- Add-device actions now use a plain plus icon instead of the add-person
  symbol.

## 4.0.23 - 2026-05-16

### Added

- Mobile test kit for the shared Rust app core plus Android and iOS
  debug builds, with simulator/device entry points for VPN dataplane,
  reconnect, LAN discovery, roster transfer, and packet-tunnel changes.
- iOS debug exit probe automation so an installed development build can
  verify exit-node HTTPS loading and route behavior from inside the app.
- ARMv6 musl daemon build helper for older Raspberry Pi targets, avoiding
  glibc and architecture mismatches during fleet updates.

### Changed

- `fips-endpoint` bumped to 0.3.10. FIPS now races active peer path
  refreshes without dropping the current session, bounds discovery retry
  work per tick, refreshes stale same-path discovery peers, and recovers
  stale FSP sessions after peer restarts/rekeys without a manual service
  bounce.
- Desktop and mobile share the same FIPS LAN path refresh and saved-peer
  hint handoff logic, so Android and iOS can use the direct-path and
  roster-refresh behavior already exercised by the daemon.
- Open FIPS discovery and health probes are throttled so public discovery
  attempts remain useful without flooding shared infrastructure.
- Mobile FIPS handshakes and packet paths are more responsive: saved
  hints seed mobile peers, reconnect handshakes are faster, iOS tunnel
  startup keeps its manager alive, packet write latency is reduced, and
  mobile can disable FIPS worker pools for lower device pressure.

### Fixed

- macOS WireGuard exit-node provider cleanup now keeps the physical
  underlay default route alive, installs split /1 tunnel routes, adds an
  unscoped endpoint bypass, and repairs stale scoped defaults instead of
  leaving the machine with broken internet after toggling an exit node.
- Xcode debug builds no longer try to link the preview injection dylib
  path that caused `__preview.dylib` build failures.
- Native apps now confirm destructive device removal, Android's top-bar
  VPN toggle is usable again, and the macOS network picker header no
  longer renders stale/incorrect state.

## 4.0.22 - 2026-05-16

### Fixed

- Daemon: cold-start and roaming reconnect time drops from ~1 minute to
  a few seconds. Two changes compose:
    * `fips-endpoint` bumped to 0.3.9. fips's open-discovery sweep now
      expedites the retry queue entry of a *configured* peer when a
      fresh overlay advert lands — previously the sweep skipped
      configured peers entirely, so on cold-start every initial
      connection attempt failed before any overlay data arrived,
      pushed the peer into the standard 5/10/20/40/80s exponential
      backoff, and we just sat on the advert until the next backoff
      slot.
    * `FipsPrivateTunnelRuntime::requires_endpoint_restart` no longer
      treats a change in `endpoint_peers.addresses` as a reason to tear
      down and re-bind the FIPS endpoint. Address hints (recent-peers
      cache) are now pushed via the new `FipsEndpoint::update_peers`
      runtime API (no link teardown), and peer-roster
      adds/removes still flow through `apply_config` →
      `mesh.replace_peers`. The pre-existing "fresh public IP observed
      → daemon restart → all peers flap offline → cold-start retry
      backoff" loop is gone.
- Recent-peers cache now passes `last_success_at` through as fips
  `PeerAddress::seen_at_ms` (introduced in 0.3.8). Cached addresses
  now race operator-supplied static hints in the same recency-ranked
  dial pass instead of sorting last for lack of a freshness signal.

## 4.0.21 - 2026-05-16

### Added

- macOS / Windows: split "Add network" and "Add device" into two
  separate flows, matching the iOS / Android shells. Header dropdowns
  now open a dedicated Add Network sheet/page (create + join with a
  manual-pairing disclosure and nearby-invites strip); admins get a
  separate "+ Add device" button on the Devices view that opens the
  invite QR + manual pairing info + add-by-Device-ID flow.
- Daemon: small disk-backed cache (`daemon.recent-peers.json`) of
  recently-connected non-LAN FIPS peer endpoints so the service can
  reconnect to peers across a restart without first reaching a Nostr
  relay, as long as the peer's IP/port haven't moved.

### Changed

- All shells: tapping "Create" in Add Network now auto-dismisses the
  sheet and navigates to the Devices tab so the user lands on the
  newly-active network instead of being stranded on the Add Network
  screen.
- `fips-endpoint` bumped to 0.3.8 — picks up the runtime-mutable peer
  list (`FipsEndpoint::update_peers`) and address recency-ranking
  (`PeerAddress::seen_at_ms`) used by the recent-peers cache above.

## 4.0.20 - 2026-05-15

### Fixed

- iOS / macOS: every TestFlight upload at the same marketing version was
  silently colliding on App Store Connect because both `ios/project.yml`
  and `macos/project.yml` hardcoded `CURRENT_PROJECT_VERSION: 1`. Apple
  uses `(CFBundleShortVersionString, CFBundleVersion)` as the unique
  build key, so the second 4.0.X build never showed up in TestFlight —
  only the first 4.0.X upload at build=1 would ever surface. Both
  project.yml files now use `${NVPN_APP_VERSION_NAME}` /
  `${NVPN_APP_VERSION_CODE}` (with `:-default` fallbacks for debug
  builds without release env). The version code is derived from the
  workspace version via `scripts/release_common.sh`'s
  `semantic_version_code` helper (4.0.20 -> 4000020), guaranteeing a
  fresh CFBundleVersion per release. `scripts/macos-build` now also
  calls `resolve_shared_build_metadata` before xcodegen so the env
  vars resolve at project-generation time (matches what `ios-build`
  was already doing).

## 4.0.19 - 2026-05-15

### Changed

- macOS / Linux: when the bundled GUI's expected service version
  doesn't match the installed background-service binary, the GUI now
  shows an always-visible header strip with an inline Update button —
  not just a small badge buried inside the System settings page.
  Wording is "Update", not "Repair", everywhere user-facing and in
  the underlying Swift / Rust names: the operation is bringing the
  daemon up to the new version, nothing's broken to repair.

### Fixed

- The VPN switch no longer flips OFF after a service update. The
  `InstallSystemService` FFI handler snapshots whether the VPN was on
  before the install and, if so, calls `connect_vpn` once the new
  daemon is reachable. Previously `nvpn service install --force`
  would tear down the old daemon and start a fresh one in
  disconnected state, leaving the user to click the toggle again.

## 4.0.18 - 2026-05-15

### Fixed

- macOS: the user-mode CLI now detects the launchd-managed service daemon
  at `/Library/PrivilegedHelperTools/to.nostrvpn.nvpn(.<config-suffix>)`.
  The May 14 stable-service-path change made the binary basename end in
  `.nvpn` instead of `/nvpn`, so the existing daemon-detection heuristic
  missed it. Effects of the miss: `nvpn status --json` reported
  `daemon.running: false` even with a healthy launchd daemon serving
  the tunnel; `nvpn pause`/`resume` rejected control requests; and the
  Mac GUI's VPN switch silently refused to turn on after a
  service-version update because it fell through to `nvpn start
  --daemon` (user-mode) which can't set up a TUN without root.

### Added

- New `scripts/e2e-macos-service.sh`: installs and uninstalls a real
  launchd service under a unique test config suffix and asserts that
  `nvpn status` sees the daemon and `pause`/`resume` work. Wired into
  the GitHub release CI's `build-macos-app` job (`macos-14` runners
  have passwordless sudo); gated locally behind
  `NVPN_RUN_MACOS_SERVICE_E2E=1` because it mutates `/Library/`.

## 4.0.17 - 2026-05-15

### Added

- macOS service install/uninstall/enable/disable now elevate through
  Authorization Services instead of `osascript`, so the system prompt uses
  Touch ID when "Use Touch ID for: Allow apps to request your password" is
  enabled in System Settings (password fallback otherwise).
- Mobile apps (iOS, Android) gained a Remove network button with a
  confirmation dialog; previously you could add saved networks but never
  delete them from the device. Mac and Windows Remove now also confirm.
- macOS gained an admin-only "Add by Device ID" card on the Share page so an
  admin can directly add another device by its identifier; iOS, Android, and
  Windows already had this. All four shells now show a brief "manual pairing
  needs both sides" explainer above the input.
- Optional Desktop shortcut task in the Windows installer.

### Changed

- The "Add by npub" UI is now consistently labelled "Add by Device ID" across
  iOS, Android, Mac, and Windows; `npub` is just a format and the user-facing
  concept is the device's identifier. Internal types and the wire format are
  unchanged.
- Device ID input fields now show a "Not a valid device ID" error and disable
  the Add button when the input is non-empty but doesn't match the
  bech32 npub1... shape, so typos are caught before dispatch.
- `scripts/local-release.mjs --publish` now also runs `scripts/publish.sh`,
  so cutting a release ships the htree tree and the Rust crates in a single
  command. Use `--skip-cargo-publish` for the htree-only flow; `--cargo-publish`
  still works on its own.

### Fixed

- Windows installer: the Start Menu shortcut's `IconFilename` pointed at
  `{app}\nostr-vpn.ico`, but `.NET` actually copies the icon to
  `{app}\Assets\nostr-vpn.ico`, so the shortcut had no usable icon. Path
  corrected.
- Windows Exit Nodes view: the right-aligned subtitles (Direct, WireGuard
  upstream, participant rows) rendered immediately to the right of the bold
  label with no gap, because WPF's `DockPanel` with `LastChildFill="True"`
  silently overrides `DockPanel.Dock` on the last child.

## 4.0.16 - 2026-05-15

### Added

- `nvpn wg-upstream-test --scoped-host` now works on Windows using the
  userspace BoringTun/Wintun runtime, which makes Windows/Linux userspace
  WireGuard baseline testing possible without replacing the Windows default
  route.

### Fixed

- Bumped FIPS to 0.3.6 so FSP rekey initiators retain and resend the final
  rekey `SessionMsg3`. This prevents one lost final rekey packet from leaving
  peers on different session keys and causing AEAD recovery churn during
  long-lived nvpn connections.
- Bumped FIPS to 0.3.7 so discovery can restart stale pending FSP sessions with
  fresh routes, stale previous-epoch drain traffic does not trigger recovery
  rekeys, and reply-learned discovery fans out through live peers even when
  tree/bloom state has a candidate.
- macOS and Linux service installation now copies the daemon to a stable
  service-owned path before writing the launchd plist or systemd unit. This
  keeps development builds from rewriting the running service executable under
  `target/release/nvpn` and causing a supervised daemon restart.

## 4.0.15 - 2026-05-13

### Fixed

- Private FIPS mesh endpoint traffic now starts routed FIPS discovery when a
  direct UDP/NAT path is down, so peers can still be reached through established
  FIPS neighbors. This is covered by the routed-FIPS Docker e2e release gate.
- Bumped FIPS to `83fbf03` so queued endpoint and TUN traffic on a stale
  half-open session starts reply-learned discovery, and transit peers forward
  lookup fallback can ask sendable non-tree peers without echoing requests to
  the origin. This keeps tree/bloom lookup routing primary while letting peers
  fall back through the mesh when direct routes, NAT traversal, or the current
  spanning-tree view are asymmetric.
- Bumped FIPS to `811eef3` so initiators resend the final XK
  `SessionMsg3` after entering `Established`. This fixes a half-established
  session failure where one peer sent encrypted endpoint traffic while the
  other peer was still waiting for the last handshake message, and keeps the
  synthetic localhost-UDP node tests reliable on slower CI runners by
  serializing the nextest group and draining synthetic handshake repairs per
  edge. The FIPS release gate also now keeps STUN-fault testing from being
  masked by LAN mDNS fallback and fixes portable timestamp checks in the DNS
  resolver harness.
- The macOS GUI refreshes participant alias edit drafts when the backend alias
  changes, so a renamed peer no longer appears under an old draft name in the
  Manage Device panel.

### Changed

- `just release-gate`, CI, and local release verification now run routed-FIPS
  and NAT safe-MTU Docker e2e tests that verify peers show online and move
  tunnel payloads both ways.
- `just release-gate`, CI, and local release verification now run a local
  `nvpn update` CLI e2e against a file-backed release manifest and archive.

## 4.0.14 - 2026-05-13

### Fixed

- macOS service repair no longer rewrites an existing config just to reinstall
  launchd. It validates the config, repairs stale root ownership when the config
  lives in a user-owned config directory, and leaves the config contents alone.
- The macOS GUI no longer displays a generated fallback network as if it were
  the user's real config after a startup config-load failure. Config-mutating
  actions now reload the real config first and refuse to save over an unreadable
  or invalid config.

## 4.0.13 - 2026-05-13

### Added

- Added `nvpn update`, a self-updater for the CLI/daemon binary. It checks the
  GitHub release API first, falls back to the htree/upload release manifest,
  selects the matching platform CLI archive, and replaces the current binary by
  default.

### Fixed

- macOS and Linux GUI update checks now prefer the GitHub release API with short
  request timeouts, keeping the htree/upload manifest as a fallback instead of
  letting update checks sit on a slow manifest request for tens of seconds.
- Service repair now preserves the existing config file owner/group when it
  rewrites the user config from an elevated daemon-install path. This prevents
  macOS repair from turning `~/Library/Application Support/nvpn/config.toml`
  into a root-owned `0600` file that the GUI cannot read.

## 4.0.12 - 2026-05-13

### Changed

- **Bumped fips-endpoint to `02c00a0` — Darwin connected-UDP and tunnel
  reliability refresh.** The macOS private mesh now installs per-peer connected
  UDP sockets by default after fixing the listener/peer `SO_REUSE*` mismatch
  that made earlier Darwin connected-socket tests unstable. On the macOS laptop
  Wi-Fi to Ethernet desktop path, the best same-window sample improved to about
  256 Mbit/s forward and 404 Mbit/s reverse; reverse is now Tailscale-level in
  current samples, while the forward direction remains packet-rate limited by
  the Darwin Wi-Fi sender path.
- Restored the private mesh default MTU budget to the IPv6-safe
  `MESH_UNDERLAY_UDP_MTU=1280` / `MESH_TUNNEL_MTU=1150`. Larger
  LAN-sized frames can work on direct Ethernet/Wi-Fi paths, but should
  be enabled only after blackhole-safe per-path probing or an explicit
  operator override; making 1420 the global default is too optimistic
  for NAT traversal and nested tunnels.
- Added an explicit private mesh MTU test lever:
  `mesh_mtu_profile = "lan"` (or `NVPN_MESH_MTU_PROFILE=lan`) selects
  a 1420-byte underlay / 1290-byte tunnel budget for clean LAN paths,
  while `mesh_underlay_udp_mtu`, `mesh_tunnel_mtu`,
  `NVPN_MESH_UNDERLAY_UDP_MTU`, and `NVPN_MESH_TUNNEL_MTU` allow
  bounded manual overrides.
- Private FIPS mesh packet routing now moves owned packet buffers through the
  send/receive hot path instead of cloning each packet at the nvpn mesh layer.
- FIPS macOS sending now defaults to the hash-by-send-target worker path instead
  of the per-flow ordered sender thread. Live macOS laptop Wi-Fi to Ethernet desktop
  testing improved the weak direction from about 103-109 Mbit/s to about
  147 Mbit/s while keeping reverse around 350 Mbit/s; the ordered path remains
  available for A/B runs with `FIPS_MACOS_ORDERED_SENDER=1`.
- FIPS macOS worker drain size can now be A/B tested with
  `FIPS_MACOS_WORKER_BATCH`; the default remains 32 after smaller batches
  regressed local Wi-Fi/Ethernet throughput.
- Added runtime-only pipeline tracing and recorded the macOS laptop/desktop and
  Docker performance experiments in `docs/EXPERIMENTS.md`.

### Fixed

- Windows WireGuard-upstream test/routing now supports the WinTun default-route
  path, including endpoint bypass, optional probe ping, hold/cleanup behavior,
  and safer script defaults for the Windows VM e2e helper.
- Completed join requests are cleared after roster updates so stale join state
  does not persist after the network accepts the request.
- LAN pairing workers now stay alive while the UI arms broadcast/discovery,
  fixing a startup race; LAN pairing, WG-upstream, and diagnostics test paths
  now use loopback-only sockets so local release checks do not trigger macOS
  firewall prompts.
- Private FIPS mesh session recovery now forces a fresh path after stale FSP
  sessions or route churn, reducing long-lived dead-link states after peer
  restart or network roaming.
- macOS/Linux private FIPS mesh writes to the TUN device now wait for fd
  writability and retry on `WouldBlock` instead of using boringtun's helper
  that collapses every write error to `0`. This avoids silent utun drops under
  sustained reverse UDP load on macOS.
- FIPS direct UDP worker sends on non-Linux now honor the bulk-data
  `drop_on_backpressure` policy instead of retrying every endpoint data packet
  indefinitely under Darwin UDP send pressure; mixed/control batches still retry
  so rekeys and handshakes are not stranded.

## 4.0.11 - 2026-05-11

### Changed

- **Bumped fips-endpoint to `9b7c723` — boringtun-style data-plane perf overhaul.** Single squash-merge landing 49 commits worth of FIPS receive/send hot-path work. **Single-stream TCP went from ~1.5 Gbps baseline to ~2.2 Gbps on Mac docker bench (+47%) and 2.24 Gbps on linux-dev netns+veth host bench (+62% over same-host baseline).** Multi-stream throughput moves up 8-15% across 4/8-stream configurations. Highlights:
  - **Shard-owned decrypt worker pool** (std::thread + crossbeam_channel) — each worker owns its session state in a thread-local HashMap. No `Arc<RwLock<HashMap>>` cache on Node, no `Arc<Mutex<ReplayWindow>>` shared with rx_loop. Direct `&mut` access per packet, zero lock acquires per AEAD layer. Hash-by-cache_key dispatch so a session always lands on the same shard.
  - **UDP_GSO on Linux** — `sendmsg(2)` + `UDP_SEGMENT` cmsg path for uniform-size batches, falling back to `sendmmsg(2)` on EINVAL/EOPNOTSUPP. Kernel splits one super-skb into N on-the-wire UDP datagrams via a single skb walk (the same primitive WireGuard kernel + boringtun use to hit 2.5–3.2 Gbps).
  - **Connected UDP per peer on Linux** — `ConnectedPeerSocket` (SO_REUSEPORT + bind + connect) for each established peer, with a `PeerRecvDrain` std::thread feeding the existing `packet_tx`. Encrypt-worker send path uses the peer's connected fd with `msg_name = NULL`; kernel skips per-packet sockaddr handling + route lookup + neighbor resolve. Pairs cleanly with UDP_GSO.
  - **Hot-path zero-copy** — UDP RX `mem::replace` (recv buffer IS the packet buffer), `SessionDatagramRef::decode` borrowed view (no inner-payload alloc on the default rx_loop path), FSP decrypt in-place on `packet_data`, eliminated `payload.drain(..6)` 1.5 KB memmove. Sender builds the FMP wire buffer in one allocation directly. Net ~150–450 MB/sec of memory bandwidth recovered.
  - **Eager session registration** — workers receive the FMP recv state at handshake completion (`promote_connection`) rather than lazily on first packet, eliminating the legacy lazy-register path entirely.
  - **`FipsEndpoint::send` SendOneway fast path** — skips the per-packet `oneshot::channel()` allocation that the old code created and immediately dropped.
  - All env-gated experimental knobs collapsed into always-on defaults. `FIPS_ENCRYPT_WORKERS` / `FIPS_DECRYPT_WORKERS` / `FIPS_TUN_QUEUES` remain as debug overrides; their default is `num_cpus`. `FIPS_CONNECTED_UDP` is removed (unconditionally on for Linux).
  - 221 node tests pass; 8 new transport/encrypt-worker unit tests pass on Linux (5 GSO + 2 ConnectedPeerSocket + 1 PeerRecvDrain).
- All-platform fips-endpoint refresh — Android, iOS, macOS, Windows, Linux, GTK, WinTun, and the CLI / daemon all pick up the new perf profile via the workspace fips-endpoint dep.

### Added

- **macOS daemon now drives WireGuard upstream end-to-end.** The "WireGuard upstream" radio item in the GUI does something on Mac for the first time: when toggled on (and a config has been pasted), the daemon's `FipsPrivateTunnelRuntime` brings up a userspace tun via boringtun, runs the WG handshake against the upstream, and **only swaps the default route to the WG tun once the handshake actually completes within a 10-second watchdog window**. If the handshake doesn't complete the routing table is deliberately left untouched, so a misconfigured config or unreachable upstream cannot blackhole the host. Toggling off, changing the config, or stopping the daemon tears the tunnel back down via a `Drop`-guard that restores the original default route + deletes the WG-endpoint bypass.
- **Same flow now wired up on Windows.** `apply_daemon_wg_upstream` on Windows creates a dedicated WinTun adapter for the WG upstream (separate from the FIPS adapter), drives the boringtun runtime against it, captures the underlay default route via `route print -4 0.0.0.0`, installs a `/32` bypass for the WG endpoint at metric=1, and adds `0.0.0.0/0` via the WG WinTun adapter at metric=1 so it wins LPM against the kernel-managed default. `WindowsFullDefaultRoute::Drop` `netsh delete`s both routes on cleanup; the original default (still in the table at its higher metric) becomes active again. Same handshake-first guarantee — if the WG handshake never completes, no `netsh` calls are made.
- `crates/nostr-vpn-cli/src/wg_upstream_runtime.rs` is now tun-source-agnostic: the boringtun pump is driven by mpsc channels for tun I/O, with platform-specific reader/writer tasks (`spawn_posix_tun_reader` / `spawn_posix_tun_writer` for Linux+macOS, `spawn_wintun_reader` / `spawn_wintun_writer` for Windows). Adds `start_with_tun` (POSIX), `start_with_wintun` (Windows), and `start_with_channels` (mobile-ready: lets a host process feed plaintext packets in/out of the WG runtime via raw channels — what an iOS NEPacketTunnelProvider or Android VpnService extension would call after the OS-side route declaration).
- FIPS mesh peer routes keep going through the FIPS tunnel even when WG upstream is up: peer `/32`s are installed before the WG default-route swap, so longest-prefix-match keeps mesh traffic on the FIPS tunnel and only "the rest of the internet" goes through Mullvad/Proton. Holds on macOS (kernel routing table) and Windows (LPM + adapter metrics) without any extra daemon code.
- New unit tests for the Windows `route print -4 0.0.0.0` parser (3 tests covering the happy path, On-link skip, and missing-default cases), runnable on all platforms via `cargo test -p nostr-vpn-cli --features embedded-fips`. The handshake-against-paired-responder integration test moved with the runtime to `nostr-vpn-core` and runs there; 109 cli + 36 core tests pass.

### Notes / not yet done

- **iOS and Android now wired up too.** The boringtun pump moved from `nostr-vpn-cli` into `nostr-vpn-core::wg_upstream` so `nostr-vpn-app-core` (the mobile crate) can use the same runtime. Platform-specific tun adapters (`start_wg_runtime_with_posix_tun`, `start_wg_runtime_with_wintun`) stay in cli; mobile uses the platform-agnostic `WgUpstreamRuntime::start_with_channels`. `MobileTunnel` now spawns the WG runtime alongside the FIPS endpoint when the user has a WG upstream config and dispatches outbound packets between the two: anything that matches a mesh peer route goes through the FIPS endpoint, anything else goes through boringtun → upstream UDP. `MobileTunnelConfig` carries `excludedRoutes` (for iOS) and `wireguardExit` (for the Rust runtime) over the JSON FFI. `nostr-vpn-core` no longer enables boringtun's POSIX-only `device` feature, so the crate cross-compiles cleanly to `aarch64-apple-ios` and `aarch64-linux-android`.
- **iOS Swift glue.** `PacketTunnelProvider.swift` reads the new `excludedRoutes` field from the JSON config and sets it on `NEIPv4Settings.excludedRoutes`. The kernel routes the encrypted UDP outside the VPN tunnel automatically — no socket-protection FFI needed.
- **Android Kotlin glue.** New JNI binding `NativeCore.mobileTunnelWgSocketFd(handle): Int` exposes the boringtun UDP socket fd. `NostrVpnService` calls `protect(fd)` after `mobileTunnelNew` so the encrypted UDP escapes the VPN tun. -1 means WG upstream isn't running, which is the default.

## 4.0.10 - 2026-05-10

### Changed

- Bumped fips-endpoint to `1abda1c`. New commits since 4.0.9:
  - `1abda1c` **encrypted: single-borrow refactor of handle_encrypted_frame fast path.** Mirrors the FSP refactor from 4.0.9 on the FMP layer. Per-thread CPU sampling on the v4.0.9 build identified one tokio worker pegged at 99.9% on a single core on both nodes during a TCP bench while 14 other workers idle, confirming the rx_loop pipeline as the single-thread bottleneck. The new shape compresses the per-packet work in `handle_encrypted_frame` from ~5 hashmap operations (sanity check + K-bit detection + decrypt + stats — three separate `peers.get(_mut)` calls) down to 2 (one immutable borrow for K-bit detection, one mutable borrow that runs decrypt + inner-header parse + MMP + link stats + touch in straight-line code), funneling the result through an `FmpFrameOutcome` enum so dispatch_link_message runs after the peer borrow is dropped. **TCP single-stream now averages ~1530 Mbps with peaks at 1552 Mbps**; multi-stream throughput moves up 2-9% (16-stream 1562 → 1575, 32-stream 1485 → 1622, 64-stream 1571 → 1623, 4-stream zerocopy 1487 → 1521 Mbps); UDP receiver ceiling rises from ~1278 to ~1306 Mbps at 1.5G load. UDP @1 Gbit stays lossless. All 1092 fips-core unit tests pass.

### Fixed

- Join-network UX overhaul, all platforms (Windows, macOS, iOS, Android, Linux GTK):
  - **"Invite Devices" and "Join Network" are now separate cards.** Sharing your network and joining someone else's are clearly distinct actions instead of sharing the same composite card. The QR / your-invite / "Broadcast invite" toggle live in *Invite Devices*; the paste field, paste-from-clipboard, scan QR, from-file picker, and the *Look for nearby* toggle + nearby-invites list live in *Join Network*.
  - **Auto-import on paste**: dropping any string starting with `nvpn://invite/` into the paste field triggers import immediately — no extra click. The field is cleared on dispatch, so the same import never re-fires and a stale invite from a previous session can't sit in the field across launches (which on Windows looked like it had been "pre-filled with the user's own invite").
  - **Scan / Paste / From-file buttons now have text labels**, not just icons (Windows, macOS, iOS, Android, Linux). Camera-only / icon-only buttons were ambiguous about what each did.
  - **Nearby pairing split into two independent 15-min toggles**: *Broadcast invite* (advertise our active network's invite over LAN) and *Look for nearby* (listen for other devices' invites). Previously a single "Pair nearby" toggle did both at once, which was confusing and meant you couldn't, say, broadcast for 15 min while not listening, or look for nearby invites without exposing your own. Each timer has its own remaining-seconds display in the button text.
- LAN pairing (`crates/nostr-vpn-app-core/src/lan_pairing.rs`): Windows now actually receives multicast invites broadcast by macOS / Linux peers on the same LAN. The previous single `join_multicast_v4(&addr, &INADDR_ANY)` left it to the OS to pick *one* interface to subscribe on, and Windows routinely picked a virtual adapter (Hyper-V vEthernet, WSL, Tailscale) instead of the physical Wi-Fi/Ethernet — so the Mac saw the Windows announcements (Mac's join was correct) but not vice versa. The new code enumerates every non-loopback IPv4 interface via `netdev`, joins multicast on each, and on every send fans out: per-interface multicast (via `set_multicast_if_v4` per send) plus a per-interface directed broadcast plus a global `255.255.255.255` last-resort. `SO_BROADCAST` is enabled so the receive side accepts all of them. Same fix applies to macOS / iOS / Android / Linux — multi-NIC hosts (Wi-Fi + Ethernet, dev VMs with several bridges) now reach peers on every L2 segment they're attached to instead of only whichever the routing table happened to prefer.
- Windows app: the read-only "your invite" display textbox (which was visually indistinguishable from the empty paste box right next to it) now sits inside the *Invite Devices* card under a clear "Your invite" caption, with the paste box moved to a separate *Join Network* card — so what looked like "the paste field is pre-filled with our own invite" is now obviously two different fields with two different roles.
- Windows app: console window no longer flashes every ~2s. The GUI's periodic `nvpn status` refresh (and other CLI invocations through `run_nvpn`) now spawn `nvpn.exe` with `CREATE_NO_WINDOW`, suppressing the conhost popup that fired on every `DispatcherTimer` tick. Implemented via a small `CommandWindowExt::hide_console_window` helper in `nostr-vpn-core::process_ext` that's a no-op on non-Windows.
- macOS Exit Nodes page: WireGuard upstream config textarea no longer wipes itself out every ~1s while typing. Each draft field (node name, endpoint, tunnel IP, listen port, MagicDNS suffix, WireGuard config) now syncs from upstream only when its own upstream value actually changes, instead of on every state-rev tick. Network-name and participant-alias drafts get the same treatment so in-flight edits survive periodic refreshes.
- Linux daemon: WireGuard upstream now activates as the local node's own egress when `wireguard_exit.enabled` is set, even if the node is not advertising itself as a mesh exit. Previously the WG tunnel was only brought up when the node was serving as an exit for the rest of the mesh, so toggling "Use WireGuard upstream" alone routed nothing through it.

### Changed

- macOS Exit Nodes page: WireGuard upstream now appears as a radio item in the same exit-target list as Direct and mesh peer exits, so the three options are mutually exclusive and visually unified. The standalone "Use WireGuard upstream" toggle is gone — selecting the radio enables it, selecting Direct or a peer disables it. The paste-config card moves to a "Configure WireGuard Upstream" disclosure that auto-expands on first run when no config has been pasted yet.

### Added

- Userspace WireGuard upstream runtime (`crates/nostr-vpn-cli/src/wg_upstream_runtime.rs`) — boringtun-based single-peer-upstream pump that brings WG-as-a-VPN-client (Mullvad / Proton style) to platforms where the daemon doesn't have a kernel-WG implementation wired in (i.e. macOS today). Owns the `Tunn`, a `UdpSocket` to the upstream, and optionally a `TunSocket`; runs three feeder tasks (timer / udp-rx / tun-rx) into a single coordinator that dispatches into `Tunn` sequentially, so the `Tunn` doesn't need a mutex.
- `nvpn wg-upstream-test --config-file <path>` is the safe-by-construction entry point: parses a wg-quick / Mullvad / Proton config, runs the userspace state machine against the upstream, reports whether the WG handshake completes within the timeout. **Without `--scoped-host`, does not create a tun device, does not modify routes** — running it can never blackhole the host's internet, even if the config is broken or the server is unreachable.
- `nvpn wg-upstream-test --scoped-host <ip>` adds the next layer: brings up a userspace tun, installs **only a single host route** to the given IP through it (default route is untouched), runs the WG handshake, then `ping`s the target through the tunnel and tears everything back down via a `Drop`-guard that runs the matching `route delete`. The host route is the only thing this can possibly break — `route delete -host <ip>` puts the host back exactly as it was even if the process is killed mid-run. Requires sudo on macOS / Linux because tun creation does.
- `nvpn wg-upstream-test --replace-default` is the dangerous mode: routes ALL outbound traffic through the WG tunnel, Mullvad/Proton-style. Designed handshake-first — the tun comes up, the WG runtime starts, and only after the WG handshake completes within `--timeout-secs` does the default route get swapped. If the handshake never completes the routing table is **never modified**, so a misconfigured config or unreachable upstream cannot take the host offline. Once the swap happens, a `FullDefaultRoute` Drop guard restores the original default + deletes the WG-endpoint bypass on cleanup, and the `--hold-secs` window catches Ctrl-C so SIGINT during the hold falls through to the revert path. Verified end-to-end in `e2e-wireguard-exit-userspace-docker.sh` stage 3.
- `apply_full_default_route(iface, address, upstream, mtu) -> FullDefaultRoute` in `wg_upstream_runtime.rs` is the reusable primitive: captures the underlay default route, installs a /32 bypass for the WG endpoint via that gateway, swaps the default to dev `<iface>`, and returns a guard whose Drop / `revert()` puts everything back. Cross-platform (Linux + macOS); will be the building block for daemon integration on macOS.
- `scripts/e2e-wireguard-exit-userspace-docker.sh` (`just e2e-wireguard-exit-userspace`) drives both stages inside Docker: stage 1 is the handshake-only probe, stage 2 brings up the userspace tun and verifies that ICMP traffic to a target on a separate subnet reachable only via the WG upstream actually traverses the tunnel (packet counter on the target asserts the source IP is the upstream's MASQUERADEd public IP, not the bridge IP).
- `scripts/e2e-wireguard-exit-docker.sh` + `docker-compose.wireguard-exit-e2e.yml` (`just e2e-wireguard-exit`) verify on Linux that an nvpn node with `wireguard_exit.enabled=true` and no advertised exit routes still routes its own internet traffic through the WireGuard upstream tunnel. The test puts the internet target on a separate subnet only reachable via the WG upstream's public-side eth, so any successful ping proves the tunnel is actually carrying the traffic, and a packet counter on the target confirms the source IP was MASQUERADEd to the upstream's public IP rather than leaking out the local bridge.

## 4.0.9 - 2026-05-09

### Changed

- Bumped fips-endpoint to `0b96f9c`. New commits since 4.0.8:
  - `0b96f9c` **udp: amortise per-packet sendto via sendmmsg(2) batching.** Per-region timing on the send hot path identified the kernel `sendto(2)` syscall as 52% of send-path CPU (2588 ns/pkt). Per-transport pending-send buffer + `sendmmsg(2)` flush at threshold (8 packets) + end-of-drain flush from the rx_loop amortises that cost across batches. Linux only; non-Linux falls through to per-packet send. **TCP single-stream 1066 → 1548 Mbps (1.45×)** on the 2-node Docker e2e bench, consistent across 1/4/8 streams. UDP @1 Gbit stays lossless at line rate.
  - `5c8deb3` udp: clippy hygiene under `-D warnings` on Linux.
  - `156cc4e` udp recv_batch: sample SO_RXQ_OVFL per batch + drop unsafe transmute on the inbound batched path.
  - `6f3d35b` **session: collapse handle_encrypted_session_msg to a single sessions borrow.** Down from 7 `self.sessions` operations per packet (`get` + `get` + `get_mut` + `remove` + `insert` + `get_mut` + `get_mut`) to one `get_mut` held inside a labeled block, with an `FspFrameOutcome` enum carrying slow-path decisions out for `&mut self` handling. Receive-side CPU drops 17.7% (3706 → 3050 ns/pkt). Throughput unchanged on its own — receive wasn't CPU-bound — but frees headroom for many-peer scaling and lower battery draw. Preserves the auto-rehandshake feature from `a38334b`.
  - `a38334b` session: auto re-handshake after consecutive AEAD decryption failures. Recovers from stale session state on either side (peer restart with new keys, etc.) without requiring a manual daemon restart.
- Cumulative bench trajectory from session start: TCP single-stream 1.57 Mbps → **1548 Mbps (~985×)**, with ring (NEON) AEAD + recvmmsg + drain batching + the FSP refactor + sendmmsg batching all stacking. The remaining gap to boringtun-`--threads=1` (3252 Mbps) is dominated by the dual-AEAD architecture (FSP + FMP encrypt per packet, vs WireGuard's single AEAD) plus the MTU difference (nvpn 1150 vs WG 1420).

## 4.0.8 - 2026-05-09

### Changed

- Bumped fips-endpoint to `6ce3bbc` to swap the AEAD from chacha20poly1305 (RustCrypto soft backend, ~600–800 MB/s/core on aarch64 because the chacha20 crate has no NEON path) to ring 0.17 (BoringSSL ChaCha20-Poly1305 with hand-tuned NEON on aarch64 and AVX2/AVX-512 on x86_64). Same wire format — fips-core's 1091 tests including IK + XK handshakes and the 100-node session test all pass byte-for-byte. ring is already transitively in the dep tree via rustls so no compile/link cost added.
- Bumped fips-endpoint to `9ca1e8b` to expose an additive off-task encrypt/decrypt API on `CipherState` and `NoiseSession` (`encrypt_with_counter[_and_aad]`, `cipher_clone`, `take_send_counter`, `accept_replay`) that lays the groundwork for a future parallel-worker pipelined dispatcher. All additive — zero behavior change on the existing rx/tx paths.
- Docker e2e bench impact (DURATION=10, identical hardware before/after):
  - 2-node direct (A↔B): TCP 1-stream 437 → 1097 Mbps (2.51×); TCP 4-stream 439 → 1109 Mbps (2.53×); TCP 8-stream 445 → 1069 Mbps (2.40×); UDP @1000 Mbit offered 599/40% loss → 1000 Mbps lossless; ping under load 0.63 → 0.71 ms.
  - 3-node forced transit (A → C → B): TCP 1-stream 438 → 1019 Mbps (2.33×); TCP 4-stream 421 → 982 Mbps; TCP 8-stream 443 → 1031 Mbps; UDP @1000 Mbit 475/52% loss → 1000 Mbps lossless; ping-under-load tail 215 → 3.6 ms max (~10× — the relay was crypto-bound, so once AEAD is NEON the queue stops accumulating).
- Cumulative trajectory from session start: TCP single-stream 1.57 → 1097 Mbps (700×); ping under load 456 → 0.71 ms (640×).

### Added

- `scripts/sync-versions.mjs` propagates the `[workspace.package].version` in `/Cargo.toml` to every other version-bearing file (linux/Cargo.toml, macos/project.yml, ios/project.yml, android/app/build.gradle.kts versionCode + versionName, Windows .csproj). Hooked into `local-release` runVerify and the `macos-build` xcodegen step so platform versions can no longer drift from the workspace silently.

### Fixed

- Service-repair recommendations now compare the installed daemon binary version against the bundled `nvpn` CLI version (queried via `nvpn version --json`) instead of against `app_version`. The new `expected_service_binary_version` field on `NativeAppState` is what `service install --force` would actually deploy, so the comparison is now apples-to-apples and stops false-positive repair prompts when the bundled CLI is at a different version than the app shell.
- Windows GUI no longer crashes at XAML startup; the `Run.Text` bindings are pinned to OneWay.

## 4.0.7 - 2026-05-09

### Fixed

- Bumped fips-endpoint to `38babf8` to pick up four upstream data-path fixes: nostr peers running an unspeakable FMP version no longer trigger a per-minute STUN-offer-answer-punch retry storm; proactive `PathMtuNotification` now feeds the path-MTU lookup so new TCP flows on long-lived paths use up-to-date MSS clamping; mid-chain ancestor swaps in deep mesh trees propagate to leaf coords (was 100% loss to non-parent destinations until depth or parent also changed); dead `SessionSetup`/`SessionAck` variants removed.

## 4.0.6 - 2026-05-09

### Fixed

- NAT-traversed sessions no longer drop full-sized tunnel datagrams. The recent 1320 B tunnel MTU bump (encrypted wire ~1426 B) silently broke any session promoted onto a NAT-traversed link, because `Node::adopt_established_traversal` was creating the adopted UDP transport with `UdpConfig::default()` (MTU 1280) and oversized packets were dropped at the socket layer. Reverted nostr-vpn-core constants to `MESH_TUNNEL_MTU=1150` / `MESH_UNDERLAY_UDP_MTU=1280`, and bumped fips-endpoint to `4031be2` so adopted transports inherit the operator's primary `[transports.udp]` config (defensive — both ends now match at 1280 regardless).

## 4.0.5 - 2026-05-09

### Fixed

- Windows release build no longer references the deleted `nostr-vpn-reflector` crate, which had been broken since the FIPS-only mesh cleanup landed.

## 4.0.4 - 2026-05-09

### Changed

- FIPS endpoint `run_rx_loop` drain cap raised from 64 to 256, keeping the worker on the hot path through ~400KB of contiguous traffic between scheduler hops. Bench: TCP single-stream 120 → 423 Mbps (+253%), UDP 200M offered 178 (11% loss) → 200 Mbps (0.0005% loss), ping under load 0.84 → 0.71 ms.

### Fixed

- macOS tray submenus stay open across state refreshes. The previous SwiftUI `MenuBarExtra` rebuilt its menu hierarchy every time the daemon state was republished (~1.5s), dismissing any open submenu within ~1s. The tray is now an `NSStatusItem` with `NSMenu` items mutated in place.

## 4.0.3 - 2026-05-09

### Fixed

- FIPS spanning-tree: nodes whose only smaller-NodeAddr parent disappeared no longer advertise an ancestry whose advertised root is not the path's minimum entry. Previously such announces were rejected by recipients with `invalid ancestry: advertised root X is not the minimum path entry Y`, blocking mesh transit (e.g. macOS desktop→linux-dev / macOS desktop→windows-dev through a shared mac peer).

## 4.0.2 - 2026-05-08

### Changed

- FIPS-backed private meshes now use the updated scoped discovery defaults, so same-LAN peers can share local candidates and prefer direct local underlay paths before routed internet paths.

### Fixed

- LAN invite broadcast remains active for 15 minutes or until cancelled, with reusable multicast sockets for multiple local app instances and Linux Docker e2e coverage for looped multicast invite exchange.

## 4.0.1 - 2026-05-08

### Added

- Exit-node leak protection can block internet access while a selected/enabled exit node is not active, with native status shown in app headers, trays, and menus.

### Changed

- WireGuard upstream setup now lives under Exit Nodes and accepts a pasted full WireGuard config block.
- Device rows now distinguish direct FIPS paths from routed FIPS paths on desktop and mobile.

### Fixed

- macOS release artifacts are signed/notarized `.dmg` downloads plus signed/notarized `.app.tar.gz` updater archives again; local and GitHub release paths now fail before publishing if signing or notarization is missing.
- GitHub macOS release builds now use the same Apple ID notarization secrets as the local release path when App Store Connect API key secrets are not configured.
- Linux, Windows, and Android GUI release artifacts are first-class release outputs again, and public release staging now fails if the app artifacts are incomplete or Android artifacts are unsigned.
- Desktop update stripes now restore the auto-install checkbox.
- Android and iOS now show the active network name outside the device rows, keep VPN on/off in the top bar, and list this device as a normal participant row instead of treating the first peer as a hero.
- WireGuard-backed exit-node providers now route their own default internet traffic through the WireGuard upstream too, while preserving the WireGuard peer endpoint on the underlay route.
- Native settings now expose the persisted WireGuard upstream fields used by exit-node providers.
- macOS no longer reapplies the FIPS utun address and peer routes on every heartbeat when the route set is unchanged.
- Linux Magic DNS falls back to managed `/etc/hosts` entries for `.nvpn` names when `systemd-resolved`/`resolvectl` is unavailable.
- New Android and iOS installs seed the editable device name from the phone/tablet instead of falling back to host-derived or generated labels.

## 4.0.0 - 2026-05-07

Changes since `0.3.23` on 2026-05-05.

### Added

- Native desktop/mobile shells now cover macOS, Linux, Windows, Android, and iOS through the shared app-core state/action contract, replacing the legacy Tauri frontend.
- FIPS is now the default private mesh data plane, with open peer discovery, mobile peer discovery, local traversal candidates, verified adverts, transit UDP, and Docker e2e coverage.
- Desktop updater e2e coverage now checks local release manifests and update asset preparation on macOS, Linux, and Windows.
- Local workflow recipes now expose platform run/build commands and build output paths.

### Changed

- macOS now uses a Tailscale-style three-column desktop layout with a toolbar VPN switch, sidebar settings, device detail actions, and daemon-level desired VPN state.
- Linux and Windows native shells were brought closer to macOS parity, including tray/deep-link/update/service behavior.
- Mobile apps now use switches for VPN on/off and keep device sharing behind the Devices plus button.

### Fixed

- Native app peer counts now exclude self devices, FIPS mesh status is surfaced consistently, and self/non-admin peer actions are hidden where they are not valid.
- macOS normal VPN on/off no longer requests administrator privileges; admin prompts are reserved for explicit background service management.
- Release validation now guards against incomplete Linux desktop asset sets and keeps versionless CLI assets in local release notes.

## 0.3.23 - 2026-05-05

Changes since `0.3.22` earlier on 2026-05-05.

### Fixed

- Linux Docker step now defaults to the host architecture (`linux/arm64` on Apple Silicon, `linux/amd64` on Intel) instead of forcing `linux/amd64`. The forced cross caused Docker to run an emulated x86_64 image under QEMU on Apple Silicon, where tauri-cli panicked with `Option::unwrap on None at rust.rs:1142` → SIGABRT during the AppImage/deb bundle step. Native-arch builds skip QEMU entirely. Override is still available via `NVPN_LINUX_DOCKER_PLATFORM` for hosts with a real x86_64 environment that want cross-arch artifacts.
- Linux artifact filenames now match the actual built arch — `*-linux-arm64.AppImage` / `*-linux-arm64.deb` and `nvpn-*-aarch64-unknown-linux-musl.tar.gz` on arm64 hosts, the `x64` / `x86_64` equivalents on amd64. Previously the script always wrote `-linux-x64` regardless of what was built.
- Linux AppImage bundling now has `xdg-mime` available in the Docker image via `xdg-utils`; Tauri's bundler calls it while assembling the AppImage.
- Local release now fails on selected platform build failures by default instead of publishing partial releases with missing assets. Use `--allow-partial` / `NVPN_RELEASE_ALLOW_PARTIAL=1` only when that is intentional.

### Changed

- `Dockerfile.linux-release`: dropped the hardcoded `rustup target add x86_64-unknown-linux-musl` so the inner build script adds whichever musl target matches the running arch. Added `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc` so aarch64 musl builds link cleanly with the same toolchain.

## 0.3.22 - 2026-05-05

Changes since `0.3.21` earlier on 2026-05-05.

### Fixed

- Linux Docker step: invoking the inner build with `bash -lc` made it a login shell, which re-sourced `/etc/profile` and dropped the rust:bookworm image's `/usr/local/cargo/bin` from PATH. `pnpm install` worked (pnpm is in /usr/bin) but the subsequent `tauri build` ran `cargo metadata` and got `bash: line 1: cargo: command not found`, surfaced by tauri-cli as the cryptic `failed to run 'cargo metadata' command…` line. Switched to `bash -c` so the Dockerfile-set PATH wins and cargo is reachable.

## 0.3.21 - 2026-05-05

Changes since `0.3.20` earlier on 2026-05-05.

### Fixed

- SystemPanel "Updates" section now keeps the muted "Last checked …" timestamp visible after a manual check instead of replacing it with the status message. The status line ("You're up to date.", "Installed …", "Available …") sits above it.
- "You're up to date." and error messages auto-clear back to idle after ~4 s — they were lingering forever, even though they aren't actionable. Available / installing / installed states still stay (those need user follow-up).
- Linux Docker release step now actually runs: forces `linux/amd64` platform (previously it inherited Apple Silicon's `linux/arm64` and would have produced mis-named aarch64 artifacts), passes `CI=true` so pnpm purges the host's macOS `node_modules` non-interactively, and snapshots the source into `/build` inside the container so the host's `node_modules` and `target/` aren't trashed cross-platform. Configurable via `NVPN_LINUX_DOCKER_PLATFORM` for hosts that prefer native arm64.

## 0.3.20 - 2026-05-05

Changes since `0.3.19` on 2026-05-04.

### Added

- Local release pipeline now builds Linux x64 desktop artifacts in Docker: signed AppImage and Debian package alongside an `x86_64-unknown-linux-musl` static CLI tarball. Uses a new `Dockerfile.linux-release` (Tauri/GTK toolchain + Rust + musl-tools); requires only Docker on the host. Wired in as the `linux` release step alongside `macos` / `android` / `windows`.

### Removed

- The boilerplate "Linux release artifacts are not built by this host script unless run on Linux or extended with a working local cross toolchain." line that the script unconditionally appended to the skipped section of release notes from non-Linux hosts. With Docker doing the Linux build natively, the disclaimer is obsolete.

## 0.3.19 - 2026-05-04

Changes since `0.3.18` earlier on 2026-05-04.

### Fixed

- In-app updater install no longer fails with `manifest was not found at manifest.json`. The plugin's `check()` defaulted `manifest_path` to `"release.json"` (matching what `htree release publish` writes), but `download_and_install()` defaulted to `"manifest.json"` — so checks succeeded and installs failed. Worked around by pinning `manifest_path: "release.json"` in `tauri.conf.json`; the plugin-side default is also being fixed upstream.

## 0.3.18 - 2026-05-04

Changes since `0.3.17` earlier on 2026-05-04.

### Changed

- macOS release artifacts: now ship a signed + notarized + stapled `.dmg` (drag-to-Applications disk image) for first-install users, alongside the `.app.tar.gz` consumed by the in-app hashtree updater. Dropped the redundant `.zip` since `.dmg` covers the human-download case more idiomatically and `.app.tar.gz` covers the updater.
- SystemPanel "Updates" status messages (`You're up to date.`, `Installed …`, available-version line, install progress, errors) now render directly under the Check button — the spot the user just clicked — instead of below the auto-check / auto-install toggles. Up-to-date and Installed states render in green.

### Fixed

- "You're up to date." was rendering below the toggle rows in muted gray, making it look like unrelated body text. It now sits beside the Check button in the success color used elsewhere in the panel.

## 0.3.17 - 2026-05-04

Changes since `0.3.16` earlier on 2026-05-04.

### Fixed

- Update banner now actually appears when an update is available. The banner used to call a 6h-throttled auto-check on mount, so once the SystemPanel "Check for updates" button had run, every subsequent launch would silently skip the check and stay hidden. Banner and SystemPanel now share a single in-memory `latestUpdate` store, the launch-time check is unthrottled (still gated on the "Check for updates automatically" pref), and SystemPanel reflects the same state — so reopening the panel after a launch check shows the available version without forcing a manual re-check. The available-update payload itself is intentionally not persisted across launches; only `lastCheckMs` and `dismissedVersion` are.

## 0.3.16 - 2026-05-04

Changes since `0.3.15` earlier on 2026-05-04.

### Fixed

- Background Service panel no longer shows "Enable the service to keep VPN control out of the GUI process" when the service is already installed and running. The instruction text + helper line now only appear when something is actually actionable (install in flight, repair recommended, or first-time setup); the steady-state panel relies on the green Installed/Running/Daemon Reachable badges and the running-pid status line.

## 0.3.15 - 2026-05-04

Changes since `0.3.14` on 2026-04-29.

### Changed

- Tauri desktop app pulls `tauri-plugin-hashtree-updater` from crates.io (`0.2`) instead of a local path checkout, so release builds no longer need the `~/src/hashtree` clone alongside the repo.
- macOS release pipeline now produces a real `.app.tar.gz` (gzipped tar of the signed/notarized `.app`) alongside the existing `.zip`, which lets the in-app hashtree updater install AppBundle updates.

## 0.3.14 - 2026-04-29

Changes since `0.3.13` on 2026-04-20.

### Fixed

- Same-port NAT recovery now skips disruptive local-endpoint punching for stale non-exit peers once that peer already has an established WireGuard runtime path, avoiding avoidable macOS tunnel churn during otherwise healthy Screen Sharing sessions.
- macOS daemon service logs are compacted in-process at startup and periodically, capping growth while retaining a recent tail for debugging.
- Default daemon logging now suppresses high-volume internal relay-pool and WireGuard timer noise, and the hot-loop macOS peer-planning line was removed.

## 0.3.13 - 2026-04-20

Changes since `v0.3.12` on 2026-04-19.

### Fixed

- Sleep, wake, and network-move recovery now clears stale peer path state, refreshes public signal endpoints, and reconnects relays immediately so peers stop sticking to obsolete public ports after resume.
- Known peers now keep receiving handshake heartbeats and targeted private announce retries until a fresh WireGuard handshake lands, reducing multi-minute reconnect stalls after missed announces or daemon restarts.

## 0.3.12 - 2026-04-19

Changes since `v0.3.11` on 2026-04-19.

### Fixed

- GitHub's Ubuntu `clippy` lane now passes again after tightening the local Nostr relay test helper and relay operator rate-sampling code for current Rust lint behavior.
- Local release automation now runs Windows guest PowerShell via encoded commands and restores the tracked Android ACL manifest after builds, avoiding quoting breakage and dirty release worktrees.

## 0.3.11 - 2026-04-19

Changes since `v0.3.10` on 2026-04-15.

### Fixed

- Same-port NAT recovery now skips disruptive local-endpoint punching for stale non-exit routed peers once another mesh peer is healthy, so working direct traffic stays up while the selected exit peer still gets aggressive recovery.
- Linux systemd service units now write daemon logs with unquoted `append:` targets, which restores `StandardOutput` and `StandardError` log redirection for the supervised daemon.

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
