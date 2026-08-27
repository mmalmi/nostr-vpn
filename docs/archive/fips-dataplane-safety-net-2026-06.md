# Historical FIPS Dataplane Safety Net - June 2026

This is a historical snapshot of the June 2026 pre-rewrite guardrail for
FIPS/nvpn dataplane work. Commands, paths, commit references, and "current"
claims below describe that work period and are not maintained as present-day
guidance. See the [maintained safety net](../fips-dataplane-safety-net.md) for
current commands and gates. The original goal was to catch queue stalls, TCP
collapse under UDP backpressure, route surprises, stale metric decisions, and
long-run degradation before changing the hot path.

## Failure Modes

- Bulk worker queues filled and stalled receive-side progress.
- Control, rekey, MMP, and liveness traffic waited behind bulk data.
- TCP-over-tunnel collapsed under UDP backpressure instead of degrading and
  recovering.
- Traffic silently used a relay, mesh fallback, or stale path when a direct UDP
  path was configured and healthy.
- macOS launchd/autoconnect route repair fought captive-portal onboarding by
  restoring or DHCP-renewing the underlay default route while the portal was
  still intercepting connectivity checks; a default-route-only portal probe can
  miss this because macOS may not expose the normal default route until the
  portal is accepted.
- Bad MMP RTT/loss/goodput samples made path or parent choice worse.
- A tunnel worked after restart, then degraded over 30-60 minutes through queue
  growth, path changes, or CPU runaway.

## Invariants

- The hot path uses bounded queues. Full queues produce explicit drop or
  backpressure signals, never hidden unbounded latency.
- Bulk packets may drop under an explicit bulk-drop policy. Control, rekey, MMP,
  liveness, and small control-shaped endpoint traffic must have a reserved lane.
- Receive loops must not park indefinitely on a full downstream bulk queue.
- One TCP-shaped flow should preserve order unless a sequencer exists.
- Static direct UDP endpoints must remain the selected path while reachable.
- Wall-clock-derived liveness and freshness decisions must reject implausibly
  far-future timestamps instead of using saturating age arithmetic as proof of
  freshness. A small same-host future skew tolerance is fine; a far-future
  `last_ping_sent_at` must not suppress control/liveness progress forever.
- macOS underlay route repair must defer when captive-portal probing has
  confirmed an active portal. On Apple platforms, that probe should try
  physical-ish underlay candidate interfaces directly before falling back to the
  default route; inconclusive probes may keep the existing repair behavior.
  The Apple socket-binding path is pinned by
  `captive_portal_check_can_bind_to_loopback_interface_on_macos`; real captive
  Wi-Fi remains separate validation.
- Stale, duplicate, regressed, or bogus MMP samples must not by themselves
  change parent/path choice.
- local Linux/docker results are not Mac-to-Mac Wi-Fi/screenshare validation.

## Queue Policy

`nostr-vpn` now makes the Unix TUN-to-mesh coordinator policy explicit:

- `TunPipelinePacket` is bulk tunnel data.
- The TUN-to-mesh channel defaults to a bounded 4096-packet bulk budget on
  Unix hosts. `NVPN_FIPS_TUN_TO_MESH_QUEUE_CAP` can override that budget for
  explicit A/B trials and is clamped to `1..65536`.
- `submit_tun_packet_to_mesh_queue` uses non-blocking `try_send`.
- A full queue returns `DroppedBulk` and increments
  `nvpn_tun_to_mesh_bulk_dropped` when `NVPN_PIPELINE_TRACE=1`.
- A closed queue returns `Closed` so the reader exits cleanly.

This pins the app-side version of the old wedge: reverting to "store one
pending packet, then await channel space" makes
`full_tun_to_mesh_queue_drops_bulk_without_waiting` fail.

FIPS-core already owns the encrypt/decrypt worker lanes. Coverage in the sibling
FIPS safety worktree includes:

- `encrypt_worker_lane_policy_keeps_endpoint_bulk_explicit`
- `encrypt_worker_shard_owns_batch_drain_and_flush_error`
- `queued_fmp_send_job_owns_lane_and_target_key`
- `queued_target_key_survives_seal_and_batch_grouping`
- `sealed_send_packet_owns_target_wire_and_drop_policy`
- `encrypt_worker_dispatch_preserves_single_flow_worker_and_fifo_order`
- `priority_flow_enters_when_bulk_flow_reaches_per_flow_cap`
- `priority_flow_enters_when_bulk_worker_queue_is_full`
- `send_backpressure`
- `pipelined_endpoint_wire_uses_reserved_counters_and_offsets`
- `pipelined_endpoint_wire_plan_owns_payload_sizing_and_worker_offsets`
- `pipelined_endpoint_dispatch_plan_owns_worker_policy_and_bookkeeping`
- `pipelined_endpoint_send_target_owns_connected_udp_preference_and_fallback`
- `pipelined_endpoint_send_plan_owns_worker_job_and_bookkeeping_handoff`
- `pipelined_endpoint_peer_runtime_route_owns_snapshot_route_policy_and_send_plan`
- `pipelined_endpoint_runtime_send_plan_owns_route_and_fmp_preparation`
- `pipelined_endpoint_runtime_send_plan_owns_peer_route_snapshot_handoff`
- `pipelined_endpoint_runtime_dispatch_owns_target_reservations_and_prepared_send`
- `peer_runtime_send_snapshot_owns_fmp_metadata_and_worker_availability`
- `peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs`
- `peer_runtime_route_decision_owns_next_hop_snapshot_weight_and_policy`
- `pipelined_endpoint_peer_runtime_send_owns_transport_path_mtu_route_plan_and_runtime_dispatch`
- `pipelined_endpoint_peer_runtime_route_request_owns_next_hop_snapshot_and_policy`
- `pipelined_endpoint_peer_runtime_send_request_owns_route_request_and_dispatch`
- `pipelined_endpoint_peer_runtime_send_request_owns_commit_bookkeeping`
- `peer_runtime_endpoint_send_facade_owns_route_dispatch_and_commit`
- `session_datagram_runtime_route_owns_next_hop_path_mtu_and_bookkeeping`
- `session_fsp_send_plan_owns_flags_coords_wire_and_bookkeeping`
- `test_pipelined_send_counter_reservation_is_single_owner`
- `fair_admission_keys_pressure_by_exact_send_target`
- `fair_admission_reservation_owns_release_key`
- `queued_fmp_send_job_owns_clamped_scheduling_weight`
- `selected_send_target_key_drives_dispatch_and_admission`
- `selected_send_batch_owns_target_fifo_and_drop_policy`
- `linux_send_batch_attempt_owns_cursor_and_backpressure_policy`
- `direct_send_batch_attempt_owns_cursor_and_backpressure_policy`
- `mac_completion_group_owns_flow_key_and_fifo_items`
- `mac_worker_prioritizes_control_when_bulk_queue_is_full`
- `mac_worker_rejects_bulk_when_bulk_queue_is_full`
- `mac_dispatch_does_not_block_rx_loop_on_full_bulk_queue`
- `fair_dispatch_does_not_block_rx_loop_on_full_bulk_queue`
- `decrypt_worker_channel_cap_prefers_specific_then_shared_value`
- `decrypt_worker_priority_packet_classifier_keeps_small_packets_reserved`
- `decrypt_job_owns_lane_selected_at_construction`
- `decrypt_fallback_event_owns_lane_selected_at_construction`
- `decrypt_worker_full_queue_drops_bulk_without_waiting`
- `decrypt_worker_priority_packet_uses_priority_lane_when_bulk_queue_is_full`
- `decrypt_worker_register_uses_priority_lane_when_bulk_queue_is_full`
- `decrypt_worker_register_full_returns_false_without_waiting`
- `decrypt_worker_drain_registers_priority_before_bulk_jobs`
- `decrypt_worker_drain_unregisters_priority_before_bulk_jobs`
- `decrypt_worker_accepts_fmp_replay_only_after_aead_success`
- `owned_session_state_open_fmp_owns_replay_acceptance`
- `session_registry_owns_established_fsp_open_lookup_and_bookkeeping`
- `open_fsp_established_frame_failed_all_epochs_does_not_consume_replay`
- `reserve_fsp_worker_send_owns_counter_header_and_cipher`
- `session_registry_owns_fsp_send_bookkeeping`
- `session_registry_owns_endpoint_fsp_worker_reservation_and_path_mtu_seed`
- `decrypt_worker_shard_owns_register_and_unregister_state`
- `decrypt_session_key_routes_registration_jobs_and_unregister_to_same_worker`
- `decrypt_worker_unregister_uses_priority_lane_when_bulk_queue_is_full`
- `decrypt_worker_unregister_full_returns_false_without_waiting`
- `decrypt_worker_fallback_event_classifier_uses_priority_and_bulk_lanes`
- `decrypt_worker_fallback_bulk_full_does_not_starve_priority_events`
- `decrypt_worker_fallback_priority_full_returns_false_without_waiting`
- `fallback_drain_prefers_ready_priority_over_selected_bulk`
- `packet_drain_cursor_interleaves_side_queues_after_fallback`
- `worker_preserves_fmp_flags_through_fallback`
- `worker_reports_fmp_aead_failure_to_rx_loop`
- `established_fsp_wire_owns_ciphertext_offset_and_coord_warmup`
- `session_registry_owns_early_encrypted_handshake_resend_budget`
- `authenticated_session_dispatch_owns_route_ce_and_completion_facts`
- `pending_route_retries_own_expiry_due_order_and_budgets`
- `local_send_failures_own_peer_scoped_fast_dead_clear_and_expiry`
- `session_direct_degradation_owns_hold_extension_expiry_and_clear`
- `discovery_fallback_transit_owns_target_exception_block_and_bootstrap_policy`
- `bootstrap_transports_own_membership_peer_npub_and_cleanup`
- `transport_drop_tracker_owns_rising_edge_state_and_cleanup`
- `pending_outbound_handshakes_own_msg2_index_matching_and_cleanup`
- `link_address_index_owns_lookup_replace_and_stale_safe_remove`
- `link_registry_owns_storage_address_index_and_stale_safe_cleanup`
- `session_index_registry_owns_lookup_replace_remove_and_peer_membership`
- `peer_lifecycle_registry_owns_active_peer_insert_and_current_session_index`
- `peer_lifecycle_registry_owns_current_session_index_repair`
- `peer_lifecycle_registry_owns_current_session_replacement_and_index_handoff`
- `peer_lifecycle_registry_owns_pending_rekey_session_and_index_registration`
- `peer_lifecycle_registry_owns_authenticated_fmp_receive_bookkeeping`
- `peer_lifecycle_registry_owns_fmp_send_bookkeeping`
- `peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths`
- `peer_lifecycle_registry_owns_fmp_rekey_initiation_target_snapshot`
- `peer_lifecycle_registry_owns_fmp_rekey_initiation_state_install`
- `peer_lifecycle_registry_owns_fmp_rekey_msg1_resend_selection_and_accounting`
- `peer_lifecycle_registry_owns_mmp_receiver_report_processing`
- `peer_lifecycle_registry_owns_mmp_receiver_report_skip_paths`
- `peer_lifecycle_registry_owns_due_mmp_link_report_collection`
- `peer_lifecycle_registry_mmp_link_report_collection_respects_modes`
- `peer_lifecycle_registry_owns_exhausted_fmp_rekey_msg1_cleanup`
- `peer_lifecycle_registry_owns_link_dead_direct_path_degradation`
- `decrypt_session_registrations_own_worker_acceptance_and_unregister_gate`
- `identity_cache_owns_prefix_validation_lru_touch_and_lookup_views`
- `configured_peer_send_weights_own_identity_parse_and_default_policy`
- `learned_route_fallback_exploration_owns_interval_dedup_and_expiry`
- `endpoint_command_tx_helper_classifies_priority_and_bulk_payloads`
- `endpoint_payload_traffic_classifier_prioritizes_control_sized_packets`
- `test_reply_learned_prefers_live_mesh_route_over_stale_direct_peer`
- `test_reply_learned_prefers_live_mesh_route_over_session_degraded_direct_peer`
- `test_reply_learned_keeps_configured_static_direct_peer_despite_session_degraded`
- `test_reply_learned_keeps_configured_static_direct_peer_over_lower_cost_fallback`
- `test_tree_routing_skips_session_degraded_direct_peer_for_payload`
- `test_stale_mmp_receiver_reports_do_not_change_route_choice`
- `test_stale_session_receiver_reports_do_not_change_route_choice`
- `test_fresh_bogus_session_metrics_without_valid_rtt_do_not_change_route_choice`
- `test_parent_reeval_ignores_unmeasured_peer_costs`
- `test_parent_reeval_ignores_fresh_bogus_metrics_without_valid_rtt`

The decrypt worker now has a bounded bulk lane plus a bounded priority lane.
Large established packets use the bulk lane and may drop when that lane is
full. Small control-shaped established packets, session registration, and
session unregister use the priority lane so MMP/rekey/heartbeat-sized traffic
does not wait behind a saturated bulk decrypt queue. The drain-order test pins
that queued priority registration is applied before queued bulk decrypt work,
so a full bulk lane cannot make the worker silently process session traffic
before it has received the session state.
The decrypt-job lane ownership guard pins the queue-message boundary on the
receive side: once rx loop builds a `DecryptJob`, that message owns the
priority/bulk lane selected from the original packet shape. Dispatch consumes
the queued lane instead of deriving it later from mutable packet bytes.
The decrypt fallback event lane ownership guard pins the worker-to-rx-loop
completion boundary: once the worker creates a `DecryptFallback`, that event
owns the priority/bulk lane used by the fallback sender, instead of deriving
queue policy later from mutable fallback metadata.
The rx-loop side-queue progress guard pins the biased scheduler contract under
hot inbound pressure: after the existing decrypt-fallback interleave, a
continuously ready raw-packet drain must also yield a bounded turn to endpoint
commands and TUN outbound work. The decrypt-fallback select arms use the same
bounded side drain before returning to `select!`, so fallback pressure cannot
make endpoint control sends or outbound tunnel packets wait for the next
maintenance tick.
The endpoint command lane ownership guard pins the app-to-rx-loop message
boundary: once `FipsEndpoint` builds a `Send` or `SendOneway` command, that
app-data command owns the bulk lane, and channel selection consumes the queued
command lane without reclassifying payload bytes later.
The endpoint send command ownership guard pins the next app-to-rx-loop message
boundary: `EndpointSendCommand` owns the remote identity, payload,
bulk lane, and queue timestamp consumed by both `Send` and
`SendOneway`, so the response and fire-and-forget variants cannot drift into
different perf-accounting or dispatch paths.
The endpoint payload policy ownership guard pins the policy selected at app
ingress: `EndpointDataPayload` owns app payload bytes as bulk/drop-on-pressure
data, pending endpoint queues store that owner, and the pipelined sender
consumes it without reclassifying raw payload bytes later.
The endpoint data send ownership guard pins the next identity/payload boundary:
`EndpointDataSend` owns the destination node address, destination public key,
and endpoint payload owner consumed by identity registration, direct send, and
pending queueing.
nvpn callers should keep endpoint npubs at config/UI/control edges where
possible. The daemon and mobile hot roster-owned send paths cache FIPS
`PeerIdentity` values keyed by normalized participant pubkey and call
`send_to_peer`; the old `send(endpoint_npub, data)` path remains only as a
compatibility/error-preserving fallback or for pre-roster join-request targets.
Mobile route dispatch uses a metadata-only mesh route lookup so the route target
can be snapshotted, the mesh lock dropped, and the original packet `Vec<u8>`
moved into endpoint send without cloning payload bytes; non-mesh packets keep
the same `Vec<u8>` for WireGuard upstream fallback.
The mobile send task drains bounded ready bursts from the OS outbound channel
and batches only consecutive packets for the same resolved FIPS peer, flushing
before MagicDNS, WireGuard upstream fallback, or peer changes.
Mobile receive mirrors that ownership shape by moving endpoint packet bytes
through node-address admission with `receive_endpoint_data_owned_from_node_addr`
after control-frame decoding, then writing the admitted packet to the mobile
inbound channel.
The mobile receive task drains endpoint messages with a bounded reusable
`recv_batch_into` buffer, so packet bursts amortize endpoint wakeups without
adding another app-side queue or changing per-message control/data handling.
The FIPS inbound endpoint event channel remains no-blocking for the node rx
loop, but is no longer invisible: `EndpointEventSender` /
`EndpointEventReceiver` own queued-message accounting across single events and
`DataBatch`, and emit `endpoint_event_backlog_high` when an embedded endpoint
consumer falls materially behind.
The pending endpoint data queue ownership guard pins the per-destination backlog
owner: `PendingEndpointDataQueue` owns bounded push/drop-oldest admission for
endpoint payloads waiting on session establishment.
The pending TUN packet queue ownership guard pins the matching packet backlog
owner: `PendingTunPacketQueue` owns bounded push/drop-oldest admission for TUN
packets waiting on session establishment.
The pending session traffic queue ownership guard pins the combined
session-establishment backlog owner: `PendingSessionTrafficQueues` owns the TUN
and endpoint destination maps, destination-cap admission, and destination
cleanup while delegating per-destination bounded enqueue policy to the narrower
queue owners.
The pending discovery lookup queue ownership guard pins route-repair admission:
`PendingDiscoveryLookups` owns in-flight lookup dedupe and queue-full decisions
before discovery backoff, bloom reachability, retry, and timeout logic continue
through the existing state machine.
The recent discovery request cache ownership guard pins reverse-path response
routing: `RecentDiscoveryRequests` owns request-id dedupe, cache capacity,
expiry, reverse-hop retention, and one-shot response-forward claims for
`LookupResponse` routing.
The pending route retry scheduling guard pins route-recovery retry ownership:
`PendingRouteRetries` owns retry-entry expiry, deterministic due ordering, the
main reconnect budget, and the smaller active direct-refresh background budget
before `process_pending_retries` initiates any connection work.
Fast reconnect is scoped to peers that actually opt into auto-reconnect. In
nvpn, private roster endpoint peers keep that policy, while bootstrap/static or
recent non-roster transit seeds are still auto-connect candidates but use finite
configured retries instead of indefinite fast retries against shared FIPS
listeners.
The local send failure ownership guard pins the local-route failure liveness
signal: `LocalSendFailures` owns per-peer local-route-failure timestamps,
fast-dead timeout selection, success clearing, non-local error ignoring, and
stale-signal expiry so one peer's OS route error cannot compress another
peer's liveness window.
The session direct degradation ownership guard pins the session-layer
route-degradation signal: `SessionDirectDegradation` owns destination-scoped
degraded holds, hold extension without duplicate transition signals, expiry
cleanup, and explicit clear behavior before route choice decides whether a
direct path should stop carrying payload traffic.
The discovery fallback-transit ownership guard pins reply-learned lookup
fanout eligibility: `DiscoveryFallbackTransit` owns ambient transit
block/unblock state, the direct-target exception, and bootstrap-transport
exclusion so discovery cannot silently route fallback fanout through a peer
that should only be used as the direct target.
The bootstrap transport bookkeeping guard pins adopted Nostr/STUN traversal
state: `BootstrapTransports` owns the bootstrap transport-id membership, the
originating peer npub used for protocol-mismatch cooldown, and cleanup of both
values when the adopted transport is no longer referenced.
The transport drop tracking guard pins kernel-drop/backpressure observability:
`TransportDropTracker` owns per-transport cumulative drop samples, rising-edge
event detection, current dropping state, and cleanup of transport state. The
rx-loop congestion check now consumes that owner instead of open-coding
`HashMap` state mutation at the forwarding boundary.
The pending outbound handshake dispatch guard pins msg2 receive-side lookup:
`PendingOutboundHandshakes` owns exact `(transport_id, our_index)` matching,
unique cross-transport index fallback for equivalent/adopted UDP replies,
ambiguity rejection, and cleanup of pending outbound handshake dispatch state.
The handshake handler now consumes that owner instead of open-coding a raw
pending map scan at the msg2 boundary.
The link address index guard pins reverse link lookup ownership:
`LinkAddressIndex` owns `(transport_id, remote_addr) -> link_id` insertion,
replacement, lookup, and stale-safe removal so stale loser cleanup cannot erase
a newer winner's route/dispatch entry for the same address.
The link registry ownership guard pins the larger link boundary:
`LinkRegistry` owns active `Link` storage and reverse address dispatch together.
Insertion updates both sides, replacing a link removes the replaced link's stale
address entry, and removal only clears the address entry if it still points to
the link being removed.
The session index registry guard pins active encrypted-frame receiver-index
dispatch: `SessionIndexRegistry` owns active `(transport_id, our_index) ->
NodeAddr` lookup, stale-owner replacement, remove-return owner, and
peer-has-other-index membership used by connected-UDP cleanup. Encrypted frame
dispatch, current-session registration repair, and deregistration now consume
that owner instead of open-coding raw map reads and removals at the session
index boundary.
The peer lifecycle session-index removal guard pins the teardown decision:
`PeerLifecycleRegistry` removes an index and returns the removed owner plus
whether that owner still has another index as one atomic result. Rekey drain can
preserve connected UDP when a new index is already installed, while last-index
peer teardown can close the connected socket without `Node` separately querying
the index map after removal.
The peer lifecycle active-peer insertion guard pins promotion state install:
`PeerLifecycleRegistry::insert_with_current_session_index` owns active peer
storage plus current receiver-index registration and reports stale owner
replacement. Initial promotion and cross-connection winner promotion consume
that operation instead of updating peer storage and receiver-index dispatch as
separate call-site steps.
The peer lifecycle current-session index repair guard pins the reconnect/repair
path for active receiver-index dispatch: `PeerLifecycleRegistry` owns
missing/stale current `(transport_id, our_index)` repair and returns a typed
registration result. `Node` keeps only logging policy for missing transport,
missing local index, already-correct, and repaired states.
The peer lifecycle current-session replacement guard pins active peer path
swaps: `PeerLifecycleRegistry::replace_current_session_and_path` owns Noise
session replacement, current indices, link/path tuple, optional remote epoch,
connected timestamp, replay-suppression accounting, and new current
receiver-index registration. It returns the old current index for `Node` to
tear down only after the new index is visible, preserving remaining-index state
for connected UDP and decrypt-worker handoff cleanup.
The peer lifecycle pending-rekey guard pins the pre-cutover rekey state:
`PeerLifecycleRegistry::install_pending_rekey_session_and_index` owns pending
Noise session storage, pending local/remote indices, optional remote-epoch
update, peer-initiated rekey dampening, and pending receiver-index
registration. Current and pending receiver indices remain visible together
until K-bit cutover/drain decides which index to tear down.
The peer lifecycle authenticated-FMP receive guard pins the hot receive-side
bookkeeping: `PeerLifecycleRegistry::record_authenticated_fmp_receive` owns
decrypt-failure reset, authenticated path rotation, link receive stats, peer
liveness touch, MMP receive counters, spin-bit observation, and the
connected-UDP clear signal returned to `Node`.
The peer lifecycle FMP send bookkeeping guard pins the hot send-side accounting
boundary: `PeerLifecycleRegistry::record_fmp_send_bookkeeping` owns active-peer
link send stats plus MMP sender counters for worker, inline fallback, and
pipelined session/datagram FMP sends.
The peer runtime send-snapshot guard pins the first `PeerRuntime`-shaped send
boundary: the peer-runtime snapshot carries the peer address, prepared FMP
metadata, and FMP worker-send availability together. Runtime dispatch consumes
that snapshot when reserving the FMP worker send, instead of rereading active
peer state after route/FMP preparation.
The peer runtime route-snapshot guard grows that boundary earlier in the send
path: `PeerLifecycleRegistry::prepare_peer_runtime_route_snapshot` reads the
active peer once and returns the next-hop peer address, transport/current
address used for path-MTU seeding, prepared-FMP inputs, and FMP worker-send
availability. Runtime send preparation derives both route planning and the FMP
send snapshot from that captured peer view.
The runtime route-snapshot handoff guard pins the next boundary:
`PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot` owns the conversion
from route plan plus send plan plus peer-route snapshot into the runtime send
plan. It derives the FMP send snapshot internally and rejects a route next-hop
that does not match the captured peer snapshot address.
The peer-runtime route owner guard pins the wider route/send policy boundary:
`PipelinedEndpointPeerRuntimeRoute` carries the captured peer-route snapshot
together with default TTL, scheduling weight, and direct-path bulk-drop policy.
The selected transport supplies path MTU at runtime-send-plan construction, so
`Node` no longer precomputes transport/current-address MTU while assembling the
route handoff.
The runtime send-attempt guard pins the next hot-path handoff:
`PipelinedEndpointRuntimeSendAttempt` carries the resolved send target plus
runtime send plan and owns FSP/FMP send reservations. It proves the no-counter
path when the FMP worker lane is unavailable, so `Node` no longer consumes
session or peer send counters while probing worker availability.
The runtime send owner guard pins the next dispatch step:
`PipelinedEndpointRuntimeSend` carries the runtime send plan, owns transport
lookup plus UDP send-target resolution, and delegates FSP/FMP reservation
handoff to the send-attempt owner. Missing transports fail before session or
peer counters move, so `Node` no longer sequences lookup, target resolution,
and reservation handoff inline.
The peer-runtime send owner guard pins the next facade:
`PipelinedEndpointPeerRuntimeSend` carries the original endpoint send plus
peer-runtime route, resolves the selected transport, derives path MTU from the
captured peer-route snapshot and transport/current-address pair, owns runtime
send-plan construction, and delegates UDP target resolution plus FSP/FMP
reservation handoff to the runtime-send owner. Missing transports still fail
before counters move, so `Node` no longer sequences transport/path-MTU lookup,
route-plan construction, and runtime dispatch inline.
The peer runtime route-decision guard pins the route-choice boundary before the
session handler sees it: `PeerRuntimeRouteDecision` owns next-hop selection,
peer-route snapshot capture, configured send weight, and direct-path bulk-drop
eligibility as one object. The endpoint/FSP route request consumes that decision
instead of assembling next-hop lookup, active-peer snapshot reads, route config,
and direct-path policy inline.
The peer-runtime route-request guard pins the route lookup and policy boundary:
`PipelinedEndpointPeerRuntimeRouteRequest` carries the source, destination,
default TTL, and decision time, resolves the next hop, asks
`PeerLifecycleRegistry` for the peer-route snapshot, applies configured send
weight, and carries direct-path degradation into the explicit bulk-drop policy.
Missing routes and FMP-preparation failures return typed request errors, so
`Node` no longer interleaves next-hop lookup, peer snapshot reads, route config,
and direct-path policy inline while preparing the endpoint/FSP send handoff.
The peer-runtime send-request guard pins the wider endpoint-send boundary:
`PipelinedEndpointPeerRuntimeSendRequest` carries the endpoint send plus route
request, resolves next-hop/snapshot/policy, and then owns dispatch preparation
through runtime send planning, UDP target resolution, and FSP/FMP reservation
handoff. `Node` now constructs one send request and commits the prepared
dispatch instead of sequencing route resolution and peer-runtime send dispatch
as separate hot-path steps.
The peer-runtime send-request execution guard pins the final hot-path
bookkeeping boundary: the same request now resolves dispatch and commits the
prepared worker job, including FSP/FMP counter reservation, session traffic
bookkeeping, outbound next-hop recording, peer link send stats, and forwarding
originated counters. `Node` now awaits the request result instead of owning the
commit sequence after route resolution.
The peer-runtime endpoint-send facade guard pins the `Node` entry point for
that owner: `Node::execute_peer_runtime_endpoint_send` now owns the transition
from endpoint payload send into route decision, UDP target resolution, FSP/FMP
reservation, and prepared worker-job commit. The hot-path caller consumes one
facade method instead of assembling the peer-runtime request and commit
plumbing inline.
The session registry FSP send bookkeeping guard pins the end-to-end send-side
accounting boundary: `SessionRegistry::record_fsp_send_bookkeeping` owns FSP
data counters, MMP sender counters, idle-touch policy, and optional outbound
next-hop recording for session data, endpoint data, pipelined session/datagram,
session-control, and standalone CoordsWarmup sends.
The peer lifecycle link-dead degradation guard pins direct-path timeout state:
`PeerLifecycleRegistry::mark_link_dead_direct_path` owns active-peer stale
marking, degraded-link reporting, and connected-UDP socket/drain teardown while
leaving the peer probeable but unhealthy for payload-routing decisions.
The peer lifecycle connected-UDP activation guard pins the activation scan:
`PeerLifecycleRegistry::connected_udp_activation_plan` owns healthy established
UDP peer eligibility, the already-installed connected-UDP count, and the stable
configured-peer-before-discovered activation order. The handler still owns async
transport resolution, socket open, and drain spawn.
The peer lifecycle connected-UDP install/clear guard pins final socket/drain
mutation: `PeerLifecycleRegistry::install_connected_udp_if_eligible` owns the
activation-race eligibility recheck and install, and
`PeerLifecycleRegistry::clear_connected_udp_for_peer` owns idempotent clear
results. The handler still owns async transport resolution, socket open, drain
spawn, budget checks, and perf/log emission.
The peer lifecycle active-peer teardown guard pins full peer-removal cleanup:
`PeerLifecycleRegistry` removes an active peer and returns a typed receiver-index
teardown plan for current, rekey, pending, and previous indices. `Node` still
performs worker deregistration, index freeing, and pending-outbound cleanup, but
it consumes the owner-produced plan instead of knowing every `ActivePeer` index
slot.
The session registry and decrypt registration guards pin the worker-handoff
gate: `SessionRegistry` owns the endpoint session table plus the rx-loop mirror
of sessions accepted by decrypt-worker shards, while
`DecryptSessionRegistrations` remains the internal mirror type. A full
registration queue must not mark the session as worker-owned, and unregister
only asks the worker to evict sessions that were actually accepted into the
local registration mirror.
The identity cache guard pins discovery/session identity lookup ownership:
`IdentityCache` owns FipsAddress/NodeAddr prefix derivation, public-key
validation, rejected-claim preservation, lookup LRU touch, LRU eviction, and
npub/pubkey read views used by discovery proof verification and endpoint
delivery.
The configured peer send-weight guard pins send-scheduling policy ownership:
`ConfiguredPeerSendWeights` owns configured-peer identity parsing, invalid
identity skipping, the explicit configured-peer scheduling weight, and the
default fallback weight used for unconfigured peers before worker fair
admission consumes the selected weight.
The learned-route fallback exploration guard pins reply-learned route-table
exploration pacing: `LearnedRouteFallbackExploration` owns selected-count
interval gating, duplicate suppression at a selected-count boundary, disabled
interval behavior, and cleanup when learned routes expire.
The rx-loop drain cursor guard pins the next completion boundary: once a
priority or bulk head item is selected, `PriorityBulkDrainCursor` owns that
selected head plus the remaining bounded drain budget. A selected bulk head
still cannot jump ahead of ready priority work, and the drain stops when its
budget is exhausted.
The raw packet drain cursor guard pins the receiver-drain boundary in front of
that fallback lane: once a packet is selected from `packet_rx`, `PacketDrainCursor`
owns the selected first packet, remaining packet budget, and fallback interleave
point. Fallback interleave can fire after the configured packet count, but it
fires only once for that boundary and the packet budget still leaves later ready
packets queued.
The TUN outbound drain cursor guard pins the adjacent outbound receiver
boundary: once a TUN packet is selected, `TunOutboundDrainCursor` owns that
selected first packet and the remaining bounded packet budget before endpoint
send work can consume it. Budget exhaustion leaves later ready TUN packets
queued instead of hiding extra latency behind an unbounded drain.
The rx-loop data-drain stats guard pins the coordinator boundary around those
drains: once packet, TUN, and endpoint drains finish, `RxLoopDataDrainStats`
owns the per-queue counts, total drained work, and data-pressure decision used
to decide whether slow maintenance must be bounded.
The rx-loop maintenance-state guard pins the next scheduler boundary: recent
data activity and the sticky slow-maintenance timeout flag live in
`RxLoopMaintenanceState`, so idle reset, data-pressure skip, and timeout
stickiness are tested as one owner instead of loose loop locals.
The unregister tests pin the teardown side of the same contract: session
registration, priority jobs, and unregister all hash to the same worker shard;
unregister uses the reserved priority lane when the bulk lane is full; and a
full priority lane reports pressure instead of parking the rx loop or hiding
stale worker-owned session state.
The unregister drain-order guard pins stale-state cleanup more tightly:
queued unregister is applied before queued bulk decrypt work for the same
session, so old-session bulk cannot keep using stale worker-owned cipher/replay
state after teardown.
The FMP replay ownership guard drives the real worker job path through an AEAD
failure, an authentic packet, and then a replay of the same counter. Failed
AEAD does not consume the worker-owned replay window; successful AEAD advances
it; and the replay is dropped before fallback plaintext or failure events.
The FSP recv ownership guard pins the session-level epoch chooser: forged or
bogus ciphertext that fails every live current/pending/previous epoch must not
consume any epoch's replay window, the later authentic frame must still open,
and only the successful epoch may advance replay state.
The FSP send reservation guard pins the established endpoint-data worker path:
the session entry reserves the FSP counter, cloned cipher, and header as one
value before the worker seals. Worker-side AEAD may use the cloned key, but it
does not own counter sequencing or mutate the session's next inline counter.
The session FSP send-plan guard pins the non-worker packet-construction path:
`SessionFspSendPlan` owns flags, coords, inner plaintext, timestamp, and
data/control bookkeeping before sealing; `SealedSessionFspSend` owns counter,
ciphertext length, final FSP payload, and bookkeeping before datagram assembly
and post-send accounting. The plan derives the CP flag from coords presence, so
service data, endpoint fallback, session control messages, and coords warmup do
not drift into separate FSP wire or bookkeeping rules.

The decrypt-worker fallback path back to rx loop is also bounded. It has a
priority fallback lane for small/control-shaped plaintext and decrypt-failure
reports, plus a bulk fallback lane for large plaintext bounces. The fallback
lane tests prove a full bulk fallback lane drops visibly without consuming
priority fallback capacity, and a full priority fallback lane reports pressure
without parking the decrypt worker or consuming bulk capacity. The rx-loop drain
helper also prefers a ready priority fallback over a bulk fallback selected by
the outer loop a moment earlier, so ACK/control-shaped fallback work does not
wait behind that selected bulk head.

The encrypt worker now names the same policy as `EncryptWorkerLane::Priority`
or `EncryptWorkerLane::Bulk`. Endpoint bulk goes to the bulk lane and may be
dropped at the worker queue boundary under pressure; control-shaped outbound
traffic uses the priority lane/reserve and does not silently become bulk.
The encrypt-worker shard guard pins the worker-local batch owner: the shard
drains at most its configured batch size, owns the reusable batch vector, and
clears it after a flush error before receiving another batch.
The queued-message guard pins the worker-queue message boundary: once a send
job becomes `QueuedFmpSendJob`, the message owns the priority/bulk lane and
exact selected send-target key used by dispatch hashing, fair admission, queue
selection, and worker drain.
The queued-key handoff guard extends that boundary through worker sealing and
Unix batch grouping: the queued target key becomes part of `SealedSendPacket`
and is handed to `SelectedSendBatch`, so the seal/send path cannot silently
derive a different grouping key later.
The sealed send-packet guard pins the seal-to-send boundary inside that shard:
after optional FSP seal plus outer FMP seal, one value owns the selected target,
the final sealed wire packet, and the drop-on-backpressure policy before macOS
completion handling or Unix send batching consumes it.
On non-macOS, the fair encrypt worker keeps bulk fairness on a bounded bulk
queue and gives priority traffic its own bounded reserve, so a saturated bulk
worker queue cannot consume the control lane. The
`priority_flow_enters_when_bulk_worker_queue_is_full` guard is the old shared
queue failure in miniature.
The selected send-target guard pins the send-side target owner: once the
rx-loop builds an `FmpSendJob`, the selected UDP socket, optional connected
socket, destination sockaddr, and target key travel together through worker
selection and fair admission. A second send fd to the same sockaddr is still a
different target with its own budget.
The fair-admission reservation guard pins the pressure-accounting owner below
that selection: a non-macOS fair-worker reservation owns the exact selected
target key until enqueue failure or receiver drain releases it. Release consumes
the reservation token instead of recomputing the flow key from mutable job
state.
The selected send-batch guard pins the next boundary: each Unix flush group
owns one selected target, a FIFO list of wire packets, and one aggregate
drop-on-backpressure policy. If a target batch contains any non-droppable
packet, the whole group retries on backpressure instead of letting neighboring
bulk packets silently turn the group into a bulk-drop send.
The Linux send-attempt guard pins the socket-loop boundary below that batch:
one attempt owns the selected target, remaining-packet cursor, send
backpressure pacer, and current-packet drop decision. A successful partial
send advances only the sent prefix; an explicit bulk-drop decision advances
exactly one current droppable packet; and non-droppable packets remain
retryable even if the pacer requests a drop.
The direct-send attempt guard pins the same boundary for non-Linux direct
senders, including the macOS default sender path: one attempt owns the selected
target, remaining-packet cursor, send backpressure pacer, and current-packet
drop decision before direct `sendto`/connected `send` calls. This is unit/logic
coverage only; real Mac-to-Mac Wi-Fi/screenshare behavior still needs
operator-local soak.
The macOS completion-group guard pins the opt-in ordered sender completion
boundary: each completion group owns the selected send-flow key and FIFO
completion list before it hands already-sealed packets to the owning flow. This
is local macOS unit/logic coverage only, not real Mac-to-Mac validation.

The UDP send backpressure pacer now has deterministic coverage for the
socket-buffer failure path: `WouldBlock` resets/yields without becoming a
bulk-drop decision, ENOBUFS/ENOMEM are classified as backpressure, explicit
drop budgets produce `DropBulk`, and sleep throttling does not reset the
sustained-pressure budget.

The pipelined endpoint-data path now builds its FMP/FSP wire layout through
small deterministic helpers. The guards parse constructed headers back out and
prove the rx-loop-reserved FMP and FSP counters are encoded in the right
layers, the link datagram header carries the intended source/destination/path
MTU, `PipelinedEndpointWirePlan` owns link plaintext and FMP payload sizing,
and the worker-owned `FspSealJob` offsets point at the FSP AAD and plaintext
tail.
The pipelined endpoint dispatch-plan guard proves one owner now computes the
endpoint FSP reservation input, FSP send bookkeeping input, bulk/control worker
lane, direct-path degradation drop suppression, drop-on-backpressure, and
scheduling weight handoff for worker dispatch.
The pipelined send-counter guard proves send workers may use cloned AEAD keys,
but counter sequencing remains owned by the session/coordinator until a later
shard move explicitly changes that ownership. Reserved counters are unique,
clone-side AEAD does not advance the session counter, and the next inline send
continues from the expected counter.

Endpoint ingress uses one helper to select the priority or bulk endpoint
command channel for both async sends and blocking sends. That keeps blocking
callers from bypassing the bounded bulk lane with large endpoint packets while
still reserving the priority lane for ACK/control-shaped packets.

Pending session-establishment queues remain bounded by destination count and
per-destination depth. When those existing bounds drop a new destination or the
oldest queued packet, FIPS emits explicit pending-session drop counters so
route/discovery stalls are visible during soaks instead of looking like silent
traffic loss.

## Harnesses

Fast deterministic tests:

```sh
./scripts/test-dataplane-safety-fast.sh list
./scripts/test-dataplane-safety-fast.sh harnesses comparison-dry-run
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath nvpn-reliability macos-route app-state
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh fips
./scripts/test-dataplane-safety-fast.sh all
just dataplane-safety-fast harnesses comparison-dry-run
```

The selectable fast runner keeps local iteration explicit. The default suite is
`harnesses comparison-dry-run`, which runs local harness self-tests and proves
the clean/stress BoringTun + wireguard-go comparison matrix maps to the expected
commands without SSH, sudo, TUN, Docker, or artifact creation. Use `core` and
`app-state` when touching those code paths. Use `nvpn-hotpath` for the TUN,
queue, and endpoint-data packet-movement checks; `nvpn-reliability` for stale
FIPS liveness, transit retry etiquette, and private-roster gates; and
`macos-route` for captive-portal probing, Apple interface-bound socket
coverage, and underlay repair policy. The aggregate `nvpn` suite runs all
three. Set `NVPN_FIPS_REPO_PATH` when nvpn/app-state tests need unreleased
local FIPS crates. Use `fips` with the same env var for focused cross-repo FIPS
reliability/observability checks (`non_reconnect`, `active_fallback`, and
`endpoint_event_queue_owns_backlog_message_count`) inside the FIPS worktree.
The runner restores `Cargo.lock` after local-FIPS nvpn cargo runs.

The underlying focused checks are:

```sh
cargo test -p nvpn raw_tun_write_keeps_fd_open_and_writes_platform_frame
cargo test -p nvpn full_tun_to_mesh_queue_drops_bulk_without_waiting
cargo test -p nvpn closed_tun_to_mesh_queue_stops_reader
cargo test -p nvpn endpoint_data_runtime_sends_and_receives_raw_packet_batch
cargo test -p nvpn endpoint_data_runtime_sends_tun_pipeline_batch_without_repacking
cargo test -p nvpn endpoint_data_runtime_recv_batch_into_reuses_buffers_and_respects_limit
cargo test -p nvpn fips_peer_liveness_rejects_far_future_presence
cargo test -p nvpn fips_peer_ping_due_recovers_from_future_timestamps
cargo test -p nvpn endpoint_config_keeps_static_transit_peers_outside_mesh_routes
cargo test -p nvpn endpoint_config_marks_default_route_peers_non_transit
cargo test -p nvpn tunnel_config_seeds_recent_outside_roster_transit_peers
cargo test -p nvpn tunnel_config_caps_recent_outside_roster_transit_peers
cargo test -p nvpn open_discovery_does_not_loosen_tun_roster_gate
cargo test -p nvpn captive_portal -- --nocapture
cargo test -p nvpn macos_underlay_route_check_throttles_route_event_storms
cargo test -p nvpn macos_underlay_route_repair_defers_only_for_confirmed_captive_portal
cargo test -p nvpn macos_default_routes_from_netstat_finds_underlay_and_utun_routes
cargo test -p nvpn macos_underlay_default_route_detection_requires_real_underlay_route
cargo test -p nostr-vpn-core two_device_private_mesh_routes_and_admits_bidirectional_packets
cargo test -p nostr-vpn-core equal_prefix_route_ambiguity_is_dropped
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
  ./scripts/test-dataplane-safety-fast.sh fips
./scripts/test-fips-perf-harness.sh
./scripts/test-fips-platform-matrix-harness.sh
./scripts/test-fips-soak-harness.sh
./scripts/test-host-pair-harness.sh
```

The host-pair harness self-test pins the route/path sanity helper used by live
host/VM soaks: a peer on the expected direct underlay IP passes, a peer on a
different transport address fails unless `ALLOW_NON_DIRECT=1`, and an
unreachable peer fails. This keeps direct-path summaries tied to an enforcement
check.

Fast FIPS ownership/type-boundary tier:

```sh
FIPS_SAFETY_WORKTREE=/path/to/fips-dataplane-safety
( cd "$FIPS_SAFETY_WORKTREE" && ./scripts/test-dataplane-ownership-fast.sh )
```

This runs `cargo fmt --check`, focused local ownership guards, local macOS queue
cfg coverage when run on macOS, `cargo check -p fips-core --release`, and a
focused Linux Docker ownership slice. Use it for pure ownership/type-boundary
changes that do not alter queueing, routing, connected UDP, maintenance timing,
or send policy.

Linux-only deterministic FIPS dataplane checks from a local developer host:

```sh
FIPS_SAFETY_WORKTREE=/path/to/fips-dataplane-safety
( cd "$FIPS_SAFETY_WORKTREE" && ./scripts/test-dataplane-safety-linux-docker.sh )
```

This Docker helper runs the Linux fair-worker queue saturation tests,
decrypt-worker full-queue tests, endpoint priority classification, link-layer
and session-layer stale/regressed ReceiverReport route-stability tests, fresh
bogus full-mode session metric route-stability tests, parent-choice metric
robustness tests, and connected-UDP budget tests. It exists because local macOS
`cargo test` exercises the Darwin worker queue cfg, not Linux fair-worker cfg.

TCP/backpressure/direct-path regression:

```sh
./scripts/e2e-fips-perf-regression-docker.sh
```

The perf gate now enables pipeline tracing by default, constrains underlay
bandwidth, shrinks `FIPS_WORKER_CHANNEL_CAP`, injects rx-loop maintenance delay,
records TCP throughput/retransmits and ping latency p95/p99, asserts per-phase
ping loss/avg/p95/p99/max budgets, prints recent pipeline queue-wait/event
counters from both nodes, and asserts per-phase direct UDP underlay byte
counters between `node-a` and `node-b`.

Each phase has p95/p99 threshold knobs (`NVPN_PERF_*_MAX_PING_P95_MS` and
`NVPN_PERF_*_MAX_PING_P99_MS`). They default to that phase's max-ping budget,
so existing runs still fail if a tail sample exceeds the max ceiling, and local
A/Bs can tighten p95/p99 without changing the script.

Use `--phase <name>` or `--phases <csv>` to narrow a run while iterating on one
metric, then run the default full matrix before committing. The equivalent env
knob is `NVPN_PERF_PHASES=<csv>`. Known phases are `clean-underlay`,
`constrained-underlay`, `worker-queue-pressure`, and `rx-maintenance-fault`;
`--list-phases` prints the current list. The default is all phases. Unknown
phases or an empty selection fail fast so targeted probes cannot silently become
no-phase runs.

Set `NVPN_PERF_OUTPUT_DIR=<dir>` to also write
`<dir>/phase-summary.tsv`, `<dir>/failure-summary.tsv`, and raw per-step probe
files under `<dir>/raw/`. Each phase row captures forward/reverse TCP Mbps and
retransmits, ping loss/avg/p95/p99/max during forward and reverse load, post-load
ping stats, direct UDP byte deltas from both nodes, and the latest FIPS and nvpn
pipeline summary lines from each node. The raw directory keeps the iperf JSON/stderr and
ping output behind those summary rows, so p95/p99 tail failures remain
inspectable after the containers have been torn down. These are the
machine-readable artifacts to diff when comparing dataplane changes.

Before relying on perf helper changes, run the local harness self-test:

```sh
./scripts/test-fips-perf-harness.sh
```

It does not start Docker. It verifies ping percentile parsing, p95/p99 latency
failures, iperf throughput/retransmit parsing, TCP throughput floor failures,
direct-underlay byte-counter progress failures, and the extended
failure-summary context fields plus raw perf artifact path/write/copy helpers.

Before relying on platform-matrix wrapper changes, run the wrapper self-test:

```sh
./scripts/test-fips-platform-matrix-harness.sh
```

It does not start Docker. It verifies scenario environment construction through
a fake runner, including the split between the isolated send-backpressure
profile and the legacy combined worker/send-backpressure profile.

Linux/docker platform-split matrix:

```sh
./scripts/e2e-fips-platform-matrix-docker.sh
```

This wraps the perf gate with short smoke durations and records
`artifacts/fips-platform-matrix/<timestamp>/summary.tsv` plus per-scenario logs.
Each matrix row includes a `phase_summary` path to the scenario's successful
phase rows and a `failure_summary` path to any threshold that aborted the
scenario. Failure rows keep the stable TSV prefix `label`, `comparison`,
`actual`, and `threshold`, then append phase/step, latest throughput,
retransmit, ping, direct-byte, and pipeline-summary context where available. Red
matrix cases therefore remain machine-readable even when a phase fails before a
complete `phase-summary.tsv` row can be written. Set
`NVPN_PLATFORM_MATRIX_ATTEMPTS=<n>` to repeat each scenario into separate
attempt logs and summaries; any failed attempt keeps the matrix red, so repeat
mode preserves intermittent failures instead of hiding them behind a later pass.
The matrix now defaults to the perf gate's `60` ping samples so the `2%` loss
ceiling has packet-count resolution; short local probes can still override this
with `NVPN_PLATFORM_MATRIX_PING_COUNT=<n>`.
Set `NVPN_PLATFORM_MATRIX_PHASES=<csv>` to pass the same phase selector through
to each scenario, which is useful for bisecting clean-underlay versus
rx-maintenance collapse without dropping the scenario-level environment matrix.
Default scenarios are:

- `connected-udp-on`
- `connected-udp-off`
- `single-encrypt-worker`
- `tight-send-backpressure`
- `tight-backpressure`

`tight-send-backpressure` keeps the shared worker channel tight while setting an
explicit normal decrypt-worker input cap, so it isolates TCP recovery under
encrypt/send backpressure. `tight-backpressure` preserves the harsher combined
profile where the shared worker cap also constrains decrypt-worker admission.

Latest full-matrix evidence recorded here at FIPS `24bff11` plus nvpn
`81359bf`, using the
default `60` ping samples: `connected-udp-on`, `connected-udp-off`,
`single-encrypt-worker`, `tight-send-backpressure`, and `tight-backpressure`
all passed all phases. The earlier `tight-backpressure` /
`rx-maintenance-fault` miss at `98.9 Mbps` was followed by a green isolated
phase rerun, three green repeated `tight-backpressure` attempts, and then a
green full default matrix rerun. Treat the combined tight row as watchlisted
rather than gone: its clean-underlay forward/reverse TCP was `123.7` /
`120.2 Mbps`, and rx-maintenance forward/reverse load TCP was `121.0` /
`133.5 Mbps`, with load/post tunnel-ping loss still at `0%`. The next
Linux/docker safety-net target in that log, a 30-minute Docker soak, passed at
FIPS `24bff11` plus nvpn `a9bfbcd`: `33` samples, direct Docker underlay selected
throughout, `0%` tunnel-ping loss both ways, FIPS SRTT within `1-3 ms`, and no
hard queue/drop/backpressure events. This cleared the local Docker gate for the
first guarded ownership-moving step; it does not imply host/VM or
Mac-to-Mac validation.

Latest exact short Docker perf checkpoint recorded here is nvpn `42f13785`
plus FIPS `12c775a`, using short smoke durations and local-FIPS patching:
clean-underlay baseline roughly `2223.2/2280.3 Mbps` with load
`2246.3/2205.6 Mbps`, constrained-underlay baseline `127.4/136.1 Mbps` with
load `132.7/132.9 Mbps`, worker-queue-pressure baseline `119.3/130.2 Mbps`
with load `130.0/124.0 Mbps`, and rx-maintenance-fault baseline
`2245.9/2260.5 Mbps` with load `2198.2/2188.6 Mbps`. Load and post-load
tunnel-ping loss stayed `0%`, direct UDP underlay counters advanced in every
phase, worker-pressure queue-full/bulk-drop counters were visible, and
`failure-summary.tsv` contained only the header. Summary hashes:
`phase-summary.tsv`
`47fc4d8e9930929cac8055e7b8ef2ed9340d6640a73cb9c6530c159b30911b95`;
`failure-summary.tsv`
`d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.

The immediately previous runtime-plan perf attempt, nvpn `0b79cfba` plus FIPS
`58f36c0`, is retained as red history: clean-underlay passed, then
constrained-underlay reverse TCP reached `94.4 Mbps` against the `100 Mbps`
floor and the remaining phases were not reached. Its summary hashes were
`phase-summary.tsv`
`f709bc24cced4ddfa6c10033c198a541f492d4d8d5b6392617abc24e588736f7` and
`failure-summary.tsv`
`2ac82a41cfe0a73734ac99e7db2db6cf718cc08113af00ddee15fe096459a85e`.
The previous `750ebb4` checkpoint also had a heavier connected-UDP-on
platform-matrix row with default `4s`/`6s` durations and `60` ping samples. Use
that as stronger health evidence for that checkpoint, not as the exact A/B row.

Use `NVPN_PLATFORM_MATRIX_SCENARIOS=connected-udp-off,tight-send-backpressure`
to run a subset. When testing sibling FIPS changes, run it with:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH="$FIPS_SAFETY_WORKTREE" \
./scripts/e2e-fips-platform-matrix-docker.sh
```

Large-mesh connected-UDP escape hatch:

```toml
[node.connected_udp]
enabled = true
fd_reserve = 512
```

All fields are optional. Omit the table to keep FIPS defaults. Set
`fd_reserve` to keep more descriptor headroom for non-connected-UDP work, or
set `enabled = false` for an explicit persisted fallback while keeping the
platform matrix `FIPS_CONNECTED_UDP=0/1` env knob for short A/B runs.
Connected-UDP peer-cap and fd-budget skips are policy signals
(`connected_udp_peer_cap_skipped`, `connected_udp_fd_budget_skipped`) and should
remain visible in pipeline/soak artifacts; actual
`connected_udp_activation_failed` remains a hard event in clean soaks.

30-60 minute docker/VM soak:

```sh
NVPN_SOAK_DURATION_SECS=1800 ./scripts/soak-fips-dataplane-docker.sh
NVPN_SOAK_DURATION_SECS=3600 ./scripts/soak-fips-dataplane-docker.sh
NVPN_DOCKER_CPU_STRESS=1 \
NVPN_DOCKER_CPU_STRESS_SIDES=remote \
NVPN_SOAK_DURATION_SECS=1800 \
./scripts/soak-fips-dataplane-docker.sh
```

The soak writes `artifacts/fips-soak/<timestamp>/samples.ndjson` plus per-epoch
status snapshots and a `metadata.json` recording whether Docker CPU stress was
enabled. It checks direct-path status before measured traffic, then
samples peer status again after tunnel ping/iperf so liveness and byte counters
describe the traffic just measured. It records tunnel ping loss/avg/p95/p99/max
both ways, short iperf bursts both ways, FIPS transport address, SRTT, byte
counters, link-layer rekey state, `last_mesh_seen_at`, `last_fips_seen_at`,
`last_fips_control_seen_at`, `last_fips_data_seen_at`, computed FIPS/control/data
last-seen ages, `last_handshake_at`, direct-probe state, Nostr traversal
failure/cooldown/skew state, retransmits, daemon CPU, and the latest FIPS/nvpn
pipeline summaries from each daemon log.
Pipeline samples include current event rates, max observed rates, seen flags,
max observed totals when the daemon log format exposes totals, and parsed
queue-wait p95/p99/max/allmax values for `endpoint_command_wait`,
`endpoint_event_wait`, `fmp_worker_queue_wait`, `transport_queue_wait`, and
`decrypt_fallback_wait`, plus priority/bulk splits when present, and
`nvpn_tun_to_mesh_queue_wait`.

Clean soaks fail on route change away from the configured direct UDP path unless
`NVPN_SOAK_ALLOW_NON_DIRECT=1`. They also fail on hard pipeline events such as
worker queue-full, bulk-drop, decrypt priority/register drops, UDP bulk drops,
connected-UDP activation failure, or nvpn TUN-to-mesh bulk drops. Connected-UDP
peer-cap/fd-budget skips are recorded as scale-policy evidence but are not hard
clean-soak failures. Pressure A/Bs that intentionally trigger hard counters should set
`NVPN_SOAK_ALLOW_QUEUE_EVENTS=1`. After the first sample, each later sample must
show FIPS sent/received byte-counter progress on both nodes and must stay within
the configured ping avg/p95/p99 and SRTT drift envelope, so long soaks catch
gradual degradation before the absolute latency ceilings are crossed. Clean
soaks also fail when daemon CPU exceeds `NVPN_SOAK_MAX_CPU_PERCENT`, or when
parsed pipeline queue-wait p95/p99 exceeds
`NVPN_SOAK_MAX_PIPELINE_QUEUE_WAIT_P95_MS` or
`NVPN_SOAK_MAX_PIPELINE_QUEUE_WAIT_P99_MS`; set `NVPN_SOAK_ALLOW_QUEUE_WAIT=1`
only for pressure A/Bs where queue buildup is intentional. Missing, non-numeric,
stale, or implausibly future `last_fips_seen_at`, `last_fips_control_seen_at`,
or `last_fips_data_seen_at` also fails the run. The generic
`NVPN_SOAK_MAX_FIPS_LAST_SEEN_AGE_SECS` defaults to `180`;
`NVPN_SOAK_MAX_FIPS_CONTROL_LAST_SEEN_AGE_SECS` and
`NVPN_SOAK_MAX_FIPS_DATA_LAST_SEEN_AGE_SECS` default to that same budget. A side whose
`rekey_in_progress` or `rekey_draining` status stays true for more than
`NVPN_SOAK_MAX_CONSECUTIVE_REKEY_SAMPLES` consecutive samples also fails the
soak; the default is `2`, so clean runs fail on the third consecutive active
rekey sample.

One-sample Docker smokes for these liveness guards passed with local FIPS
patching enabled. Generic liveness first recorded fresh last-seen ages of `3s`
and `2s`; after adding the post-traffic status sample and data freshness gate,
a skip-build smoke using the already-built local-FIPS-patched compose images
recorded fresh data ages of `0s` and `2s`.

Before relying on a Docker soak result, run the local harness self-test:

```sh
./scripts/test-fips-soak-harness.sh
```

It does not start Docker. It verifies ping percentile parsing, absolute p95/p99
latency failures, p95/p99 drift failures, FIPS byte-counter no-progress
failures, daemon CPU threshold failures, pipeline queue-wait parsing,
queue-wait threshold failures, stuck-rekey policy, hard pipeline event policy,
fresh `last_fips_seen_at`, `last_fips_control_seen_at`, and
`last_fips_data_seen_at` liveness policy, and connected-UDP peer-cap skip
observability.

Local-to-Linux/VM host-pair baseline or soak:

```sh
NVPN_HOST_PAIR_PREFLIGHT=1 \
NVPN_HOST_PAIR_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_HOST_PAIR_EXPECTED_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_HOST_PAIR_EXPECTED_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
./scripts/soak-fips-dataplane-host-pair.sh

NVPN_HOST_PAIR_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_HOST_PAIR_EXPECTED_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_HOST_PAIR_EXPECTED_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_HOST_PAIR_DURATION_SECS=1800 \
./scripts/soak-fips-dataplane-host-pair.sh
```

This host-pair harness assumes the local daemon and the SSH-reachable Linux/VM
peer are already configured and running. It writes
`artifacts/fips-host-pair/<timestamp>/samples.ndjson`, a sanitized
`summary.tsv`, status snapshots, ping logs, iperf JSON, and on failure a
sanitized `failure.json` with the current sample number, artifact paths, latest
ping/iperf/SRTT/counter/CPU values when available, and the active thresholds.
Each sample records tunnel ping both ways, TCP iperf forward and reverse (`-R`),
peer transport address, FIPS SRTT, FIPS byte counters, link-layer rekey state,
`last_mesh_seen_at`, `last_fips_seen_at`, `last_fips_control_seen_at`,
`last_fips_data_seen_at`, computed FIPS/control/data last-seen ages,
`last_handshake_at`, direct-probe state, Nostr traversal failure/cooldown/skew
state, daemon CPU, retransmits, ping loss/avg/p95/p99/max, and optional latest
FIPS/nvpn pipeline summary lines from daemon logs. Host-pair `failure.json`
records the latest direct-probe, Nostr traversal, and last-seen state as
observability. Stale generic, control, or data FIPS freshness is also a hard
failure. `NVPN_HOST_PAIR_MAX_FIPS_LAST_SEEN_AGE_SECS` defaults to `180`, and
`NVPN_HOST_PAIR_MAX_FIPS_CONTROL_LAST_SEEN_AGE_SECS` /
`NVPN_HOST_PAIR_MAX_FIPS_DATA_LAST_SEEN_AGE_SECS` default to the same budget.
`summary.tsv` appends `fips_liveness_checked`,
`local_last_fips_seen_age_secs`, `remote_last_fips_seen_age_secs`,
`fips_control_liveness_checked`, `local_last_fips_control_seen_age_secs`,
`remote_last_fips_control_seen_age_secs`, `fips_data_liveness_checked`,
`local_last_fips_data_seen_age_secs`, and
`remote_last_fips_data_seen_age_secs`, followed by latest local/remote rekey,
direct-probe, and Nostr traversal state. When
pipeline lines are present, `samples.ndjson` also stores
parsed queue-wait p95/p99/max/allmax values for `endpoint_command_wait`,
`endpoint_event_wait`, `fmp_worker_queue_wait`, `transport_queue_wait`, and
`decrypt_fallback_wait`, plus priority/bulk splits when present, and
`nvpn_tun_to_mesh_queue_wait`. The harness infers
daemon log paths from `nvpn status`, or you can set
`NVPN_HOST_PAIR_LOCAL_DAEMON_LOG` and `NVPN_HOST_PAIR_REMOTE_DAEMON_LOG`. If a
side needs a wrapper such as sudo for status or log reads, use
`NVPN_HOST_PAIR_*_NVPN_COMMAND` and `NVPN_HOST_PAIR_*_LOG_READ_COMMAND`. Set
`NVPN_HOST_PAIR_REQUIRE_PIPELINE_LOGS=1` to fail when configured or discovered
logs have no `pipe`/`nvpn-pipe` summaries. It fails on unreachable peers,
latency/SRTT drift, CPU runaway,
consecutive TCP iperf collapse, no byte-counter progress after the first sample,
stuck rekey state, hard queue/drop pipeline events, and queue-wait p95/p99
threshold violations when summaries are present. It also fails if
`last_fips_seen_at`, `last_fips_control_seen_at`, or `last_fips_data_seen_at` is
missing, non-numeric, too old, or implausibly far in the future. Host-pair
checks compare the remote peer timestamp against the remote host clock to avoid
local/remote clock-skew false failures. Once a pipeline
summary stream has produced at least one line, the line count must keep
advancing; more than
`NVPN_HOST_PAIR_MAX_CONSECUTIVE_PIPELINE_STALE_SAMPLES` consecutive stale
samples fails the run. `rekey_in_progress` or
`rekey_draining` staying true for more than
`NVPN_HOST_PAIR_MAX_CONSECUTIVE_REKEY_SAMPLES` consecutive samples fails the
run; the default is `2`, so clean runs fail on the third consecutive active
rekey sample. Use `NVPN_HOST_PAIR_ALLOW_QUEUE_WAIT=1` only for
pressure A/Bs where queue buildup is intentional. When the expected underlay IP
variables are set, it also fails if either side silently leaves the intended
direct UDP path; omit them only for exploratory fallback runs or set
`NVPN_HOST_PAIR_ALLOW_NON_DIRECT=1`. The EXIT trap always attempts to clean up
the remote iperf server. Run `NVPN_HOST_PAIR_PREFLIGHT=1` first to check local
tools, remote SSH/tool availability, daemon-status shape, peer selection,
tunnel IP presence, and expected direct-path reachability without starting the
long sample loop. It writes `preflight.tsv` in the selected artifact directory
with `ok`/`missing` check names plus a detail column for peer counts, selected
peer/path fields, SRTT, and SRTT freshness; treat the generated preflight
artifact as local operational evidence.

For CPU-contention reliability checks, use the same host-pair soak with opt-in
background CPU stress. This is the nvpn side of the comparison with the
userspace WireGuard reference harness below:

```sh
NVPN_HOST_PAIR_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_HOST_PAIR_EXPECTED_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_HOST_PAIR_EXPECTED_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_HOST_PAIR_CPU_STRESS=1 \
NVPN_HOST_PAIR_CPU_STRESS_SIDES=remote \
NVPN_HOST_PAIR_CPU_STRESS_WORKERS=auto \
./scripts/soak-fips-dataplane-host-pair.sh
```

`auto` caps CPU stress at four busy workers per stressed side. The host-pair
metadata records whether stress was enabled, which side was stressed, and the
actual worker counts. Under stress, the reliability signal is route/session
continuity, direct-path byte progress, ping tail latency, SRTT drift, queue
residence, and daemon CPU, not just a single TCP Mbps number.

Before relying on a host/VM soak result, run the local harness self-test:

```sh
./scripts/test-host-pair-harness.sh
```

It does not contact a remote host. It verifies strict direct-path enforcement
and the explicit `ALLOW_NON_DIRECT` escape hatch, required pipeline-log mode
failures, stale pipeline summary policy, hard queue/drop counter policy,
rounded-down bare hard counters,
queue-wait p95/p99 parsing and gating, no-progress byte counters, CPU runaway,
CPU-stress helper validation, stuck-rekey policy, sample JSON queue-wait and
rekey fields, and summary coverage flags, plus CPU-stress metadata shape and
preflight artifact detail writing.

Userspace WireGuard host-pair reference baseline:

```sh
NVPN_WG_HOST_PAIR_PREFLIGHT=1 \
NVPN_WG_HOST_PAIR_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_WG_HOST_PAIR_BACKEND=boringtun \
./scripts/bench-userspace-wg-host-pair.sh

NVPN_WG_HOST_PAIR_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_WG_HOST_PAIR_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_WG_HOST_PAIR_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_WG_HOST_PAIR_BACKEND=boringtun \
NVPN_WG_HOST_PAIR_LOCAL_BACKEND_BIN="$LOCAL_BORINGTUN_CLI" \
NVPN_WG_HOST_PAIR_REMOTE_BACKEND_BIN="$REMOTE_BORINGTUN_CLI" \
./scripts/bench-userspace-wg-host-pair.sh
```

This baseline creates a temporary two-peer userspace WireGuard tunnel using
`boringtun-cli` or `wireguard-go`, then records tunnel ping both ways, TCP
iperf forward/reverse, retransmits, `wg show` snapshots, backend process CPU,
backend logs, and a sanitized `summary.tsv` under
`artifacts/userspace-wg-host-pair/<timestamp>/`. It is a reference ceiling and
latency-shape probe for the same local-to-Linux/VM underlay; it does not replace
the nvpn/FIPS safety harness because it has no nvpn queue, route, MMP, or
daemon observability. The script is environment-driven so hostnames, SSH
aliases, underlay IPs, binary paths, and interface choices stay out of committed
files. Run `NVPN_WG_HOST_PAIR_PREFLIGHT=1` first to check local/remote command
availability, remote sudo/TUN readiness, underlay env presence, and local
sudo/root/helper readiness without creating keys, interfaces, routes, backend
processes, or remote temp directories. Preflight writes a sanitized
`artifacts/userspace-wg-host-pair/<timestamp>/preflight.tsv` containing only
`ok`/`missing` check names, not hostnames, IPs, keys, binary paths, or interface
choices. The live benchmark needs sudo for local address/route changes; set
`NVPN_WG_HOST_PAIR_INTERACTIVE_SUDO=1` only for operator-local runs. For an
unattended native local-to-Linux/VM run, prefer a narrow root-owned helper over
broad passwordless sudo: install `scripts/nvpn-wg-host-pair-priv-helper` outside
the repo with root ownership and point
`NVPN_WG_HOST_PAIR_LOCAL_PRIV_HELPER` at that installed helper. The helper only
accepts check, local interface configure, `wg set`, `wg show`, and cleanup
actions; private key material is passed to `wg set` over stdin. Privileged
helper actions also refuse to run if the helper path or privileged command
binary path is not rooted in root-owned, non-group/world-writable files and
directories. A user-writable package-manager `wg` should be copied or installed
to a trusted operator-local path before using a passwordless helper rule.

For CPU-contention comparisons against the same underlay, run the same harness
with background CPU pressure on the local side, remote side, or both. Use this
as a reference row for nvpn/FIPS host-pair or Mac-to-Mac work, not as a claim
that WireGuard and nvpn have identical semantics:

```sh
NVPN_WG_HOST_PAIR_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_WG_HOST_PAIR_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_WG_HOST_PAIR_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_WG_HOST_PAIR_BACKEND=wireguard-go \
NVPN_WG_HOST_PAIR_CPU_STRESS=1 \
NVPN_WG_HOST_PAIR_CPU_STRESS_SIDES=remote \
NVPN_WG_HOST_PAIR_CPU_STRESS_WORKERS=auto \
./scripts/bench-userspace-wg-host-pair.sh
```

`NVPN_WG_HOST_PAIR_CPU_STRESS_WORKERS=auto` caps each stressed side at four
busy workers to keep occasional reference runs useful without turning the host
into an uncontrolled system benchmark. The summary and metadata record whether
CPU stress was enabled, which sides were stressed, and how many workers were
started on each side.

After running an nvpn/FIPS host-pair row and a userspace WireGuard reference row
with matching underlay and CPU-stress settings, normalize the artifact summaries
into one comparison bundle:

```sh
./scripts/compare-host-pair-benchmarks.sh \
  "$NVPN_HOST_PAIR_ARTIFACT_DIR" \
  "$NVPN_WG_HOST_PAIR_ARTIFACT_DIR"
```

The comparison helper reads only existing artifacts. It writes
`comparison.tsv`, `ratios.tsv`, and `comparison.json` under
`artifacts/host-pair-comparisons/<timestamp>/` by default. The normalized rows
preserve forward/reverse TCP Mbps, retransmits, ping p95/p99 both ways, CPU
stress settings, CPU samples, nvpn direct-path/pipeline/counter-progress
coverage flags, TCP-collapse counts, and the nvpn FIPS/control/data liveness
flags and ages when the nvpn artifact includes them. It also carries latest
nvpn rekey, direct-probe, and Nostr traversal state from newer host-pair
artifacts. The ratio file reports nvpn forward/reverse Mbps as a percentage of
the reference row, which makes numbers such as `417/360 Mbps` interpretable
against the same host-pair path instead of against an unrelated Docker run.

For an operator-local run that launches both rows with shared settings and then
normalizes them, use the comparison runner. It assumes the nvpn/FIPS daemons are
already configured and running for the nvpn row, and the userspace WireGuard
reference still needs its sudo/TUN prerequisites:

```sh
NVPN_HOST_PAIR_COMPARISON_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_HOST_PAIR_COMPARISON_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_HOST_PAIR_COMPARISON_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_HOST_PAIR_COMPARISON_BACKEND=wireguard-go \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS=1 \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES=remote \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS=auto \
./scripts/run-host-pair-comparison.sh
```

To compare nvpn/FIPS against both supported userspace WireGuard references in
one operator-local bundle, use `NVPN_HOST_PAIR_COMPARISON_BACKENDS`:

```sh
NVPN_HOST_PAIR_COMPARISON_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_HOST_PAIR_COMPARISON_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_HOST_PAIR_COMPARISON_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_HOST_PAIR_COMPARISON_BACKENDS=boringtun,wireguard-go \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS=1 \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES=remote \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS=auto \
./scripts/run-host-pair-comparison.sh
```

To capture a same-window clean baseline and CPU-contention row for each
reference backend, add `NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES`:

```sh
NVPN_HOST_PAIR_COMPARISON_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_HOST_PAIR_COMPARISON_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_HOST_PAIR_COMPARISON_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_HOST_PAIR_COMPARISON_BACKENDS=boringtun,wireguard-go \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES=clean,stress \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES=remote \
NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS=auto \
./scripts/run-host-pair-comparison.sh
```

`just dataplane-host-pair-comparison` is the same live benchmark entry point
with defaults for `NVPN_HOST_PAIR_COMPARISON_BACKENDS=boringtun,wireguard-go`,
`NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES=clean,stress`,
`NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES=both`, and
`NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS=auto`. The runner also performs
an nvpn/FIPS host-pair preflight before each nvpn row by default; set
`NVPN_HOST_PAIR_COMPARISON_NVPN_PREFLIGHT=0` only when intentionally reusing a
known-good setup. It still requires the operator-local SSH target and underlay
IP env so hostnames and addresses stay out of committed files. Use
`just dataplane-host-pair-comparison-dry-run` or
`./scripts/test-dataplane-safety-fast.sh comparison-dry-run` to verify command
mapping without touching a remote host.

When validating a newly built status client against already-running daemons, set
`NVPN_HOST_PAIR_COMPARISON_LOCAL_NVPN` and
`NVPN_HOST_PAIR_COMPARISON_REMOTE_NVPN` to the local and remote binaries. The
`*_LOCAL_NVPN_COMMAND` and `*_REMOTE_NVPN_COMMAND` variants are also forwarded
for wrapper scripts that must add environment or path setup before `status`.
These knobs do not install or restart daemons; freshness fields such as
`fips_srtt_age_ms` still require daemon code new enough to publish them.

Set `NVPN_HOST_PAIR_COMPARISON_DRY_RUN=1` first to print the exact mapped
commands without SSH, sudo, or TUN access. For one backend, the runner writes a
single bundle under `artifacts/host-pair-comparison-runs/<timestamp>/` with
`nvpn/`, `reference/`, and `comparison/` subdirectories. For multiple backends,
it runs the nvpn/FIPS row once, then writes backend-specific
`reference-<backend>/` and `comparison-<backend>/` subdirectories plus a
`manifest.tsv` at the bundle root. With multiple CPU-stress modes, each mode
gets its own `clean/` or `stress/` subdirectory containing that mode's
`nvpn/`, reference, and comparison artifacts; the manifest records mode,
backend, CPU-stress setting, and artifact paths. Live runs also write root
`matrix-summary.tsv`, `matrix-stress-deltas.tsv`, `matrix-reliability.tsv`,
`matrix-reliability.json`, and `matrix-summary.json` files. The summary table
flattens every mode/backend comparison into one row, including nvpn/reference
throughput, retransmits, p99 ping, CPU samples, nvpn Mbps as a percentage of
the reference row, nvpn direct-path/pipeline/counter-progress coverage flags,
concrete pipeline hard-event names, TCP-collapse counts, nvpn FIPS/control/data
liveness flags and ages, and latest nvpn rekey/direct-probe/Nostr traversal
state. Direct-probe columns include pending/after, retry count, auto-reconnect
policy, expiry, and
consecutive pending/overdue counters so retry-storm investigations can
distinguish bounded transit retry from roster-owned fast reconnect. The
reliability table condenses those safety fields into `pass`/`warn`/`fail` plus
reason lists for unchecked safety coverage, TCP collapse, missing liveness,
stuck rekey, overdue direct probes, active rekey/drain, direct-probe pending,
and traversal cooldown/failures. The JSON also includes `stress_deltas[]`;
when a backend has matching `clean` and `stress` rows, the delta entry reports
nvpn/reference forward and reverse Mbps under stress as a percentage of clean,
p99 ping deltas, CPU deltas, and the change in nvpn Mbps as a percentage of
the reference row. To rebuild those
summaries from an existing bundle, run:

```sh
./scripts/summarize-host-pair-comparison-run.sh \
  "$HOST_PAIR_COMPARISON_RUN_DIR"
```

Before relying on a userspace WireGuard host-pair row, run the local helper
self-test:

```sh
./scripts/test-userspace-wg-host-pair-harness.sh
./scripts/test-host-pair-comparison-harness.sh
./scripts/test-host-pair-comparison-runner.sh
```

It does not create a TUN device or contact a remote host. It verifies backend
command construction, ping p95/p99 parsing, iperf throughput/retransmit parsing,
backend validation, run-bundle summary fan-in, privileged-helper validation/wiring,
trusted-path rejection,
CPU-stress helper validation, CPU-stress summary/metadata shape, preflight
blocker reporting, preflight detail fan-in, and comparison artifact
normalization/ratio generation, clean/stress delta generation, plus dry-run
command mapping for the comparison runner including the default nvpn/FIPS
preflight step.

Useful A/B knobs:

```sh
NVPN_SOAK_CONNECTED_UDP=0
NVPN_SOAK_CONNECTED_UDP=1
NVPN_SOAK_ENCRYPT_WORKERS=1
NVPN_SOAK_DECRYPT_WORKERS=0
NVPN_SOAK_WORKER_CHANNEL_CAP=8
NVPN_SOAK_DECRYPT_WORKER_CHANNEL_CAP=8
NVPN_SOAK_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP=256
NVPN_SOAK_ALLOW_QUEUE_EVENTS=1
NVPN_SOAK_MAX_PING_P95_MS=500
NVPN_SOAK_MAX_PING_P99_MS=750
NVPN_SOAK_MAX_PING_AVG_DRIFT_MS=25
NVPN_SOAK_MAX_PING_AVG_DRIFT_FACTOR=10
NVPN_SOAK_MAX_PING_P95_DRIFT_MS=50
NVPN_SOAK_MAX_PING_P95_DRIFT_FACTOR=10
NVPN_SOAK_MAX_PING_P99_DRIFT_MS=75
NVPN_SOAK_MAX_PING_P99_DRIFT_FACTOR=10
NVPN_SOAK_MAX_SRTT_DRIFT_MS=50
NVPN_SOAK_MAX_SRTT_DRIFT_FACTOR=10
NVPN_SOAK_MAX_PIPELINE_QUEUE_WAIT_P95_MS=50
NVPN_SOAK_MAX_PIPELINE_QUEUE_WAIT_P99_MS=100
NVPN_SOAK_ALLOW_QUEUE_WAIT=1
NVPN_HOST_PAIR_CPU_STRESS=1
NVPN_HOST_PAIR_CPU_STRESS_SIDES=remote
NVPN_HOST_PAIR_CPU_STRESS_WORKERS=auto
FIPS_DECRYPT_WORKER_CHANNEL_CAP=8
FIPS_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP=256
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4
NVPN_PERF_DECRYPT_WORKER_QUEUE_PRESSURE_CAP=4
NVPN_WG_HOST_PAIR_CPU_STRESS=1
NVPN_WG_HOST_PAIR_CPU_STRESS_SIDES=remote
NVPN_WG_HOST_PAIR_CPU_STRESS_WORKERS=auto
NVPN_PLATFORM_MATRIX_TIGHT_WORKER_CHANNEL_CAP=4
NVPN_PLATFORM_MATRIX_TIGHT_SEND_DECRYPT_WORKER_CHANNEL_CAP=32768
NVPN_PERF_PIPELINE_TRACE=1
NVPN_HOST_PAIR_DURATION_SECS=1800
NVPN_HOST_PAIR_REQUIRE_IPERF=1
NVPN_HOST_PAIR_ALLOW_QUEUE_EVENTS=1
NVPN_HOST_PAIR_ALLOW_QUEUE_WAIT=1
NVPN_HOST_PAIR_MAX_PING_P95_MS=500
NVPN_HOST_PAIR_MAX_PING_P99_MS=750
NVPN_HOST_PAIR_MAX_PIPELINE_QUEUE_WAIT_P95_MS=50
NVPN_HOST_PAIR_MAX_PIPELINE_QUEUE_WAIT_P99_MS=100
NVPN_HOST_PAIR_MIN_IPERF_MBPS=0.001
NVPN_HOST_PAIR_MAX_CONSECUTIVE_IPERF_COLLAPSES=2
NVPN_HOST_PAIR_LOCAL_PEER=<remote-participant-pubkey>
NVPN_HOST_PAIR_REMOTE_PEER=<local-participant-pubkey>
NVPN_HOST_PAIR_LOCAL_DAEMON_LOG=<local-daemon-log>
NVPN_HOST_PAIR_REMOTE_DAEMON_LOG=<remote-daemon-log>
NVPN_WG_HOST_PAIR_BACKEND=boringtun
NVPN_WG_HOST_PAIR_THREADS=1
NVPN_WG_HOST_PAIR_BACKEND=wireguard-go
```

## Baseline Capture

Record current architecture before refactoring:

```sh
NVPN_PERF_DURATION_SECS=8 \
NVPN_PERF_LOAD_DURATION_SECS=12 \
./scripts/e2e-fips-perf-regression-docker.sh

NVPN_SOAK_DURATION_SECS=1800 \
./scripts/soak-fips-dataplane-docker.sh

NVPN_HOST_PAIR_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_HOST_PAIR_EXPECTED_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_HOST_PAIR_EXPECTED_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_HOST_PAIR_DURATION_SECS=1800 \
./scripts/soak-fips-dataplane-host-pair.sh

NVPN_WG_HOST_PAIR_SSH="$LINUX_OR_VM_SSH_TARGET" \
NVPN_WG_HOST_PAIR_LOCAL_UNDERLAY_IP="$LOCAL_UNDERLAY_IP" \
NVPN_WG_HOST_PAIR_REMOTE_UNDERLAY_IP="$REMOTE_UNDERLAY_IP" \
NVPN_WG_HOST_PAIR_BACKEND=boringtun \
./scripts/bench-userspace-wg-host-pair.sh
```

Keep the command output or `samples.ndjson` with the branch/commit SHA. The
minimum useful baseline row is:

- forward and reverse TCP Mbps
- retransmits
- ping loss/avg/p95/p99/max during and after TCP load
- direct UDP underlay byte deltas
- FIPS `endpoint_command_wait` / `endpoint_event_wait` /
  `fmp_worker_queue_wait` / `transport_queue_wait` /
  `decrypt_fallback_wait` p95/p99, including priority/bulk splits when present,
  `encrypt_worker_queue_full`, `encrypt_worker_bulk_dropped`,
  `decrypt_worker_queue_full`, `decrypt_worker_bulk_dropped`,
  `decrypt_worker_register_full`, `decrypt_worker_priority_dropped`,
  `decrypt_fallback_bulk_dropped`, `decrypt_fallback_priority_dropped`,
  `pending_tun_destination_dropped`, `pending_tun_packet_dropped`,
  `pending_endpoint_destination_dropped`, `pending_endpoint_packet_dropped`,
  `endpoint_event_backlog_high`, `udp_send_backpressure`, and
  `udp_send_bulk_dropped`
- `nvpn_tun_to_mesh_queue_wait` p95/p99 and `nvpn_tun_to_mesh_bulk_dropped`
- FIPS SRTT and transport address
- FIPS link-layer rekey state and consecutive stuck-rekey sample count
- daemon CPU percent

Current Docker VM baseline for this branch:

- `docs/baselines/fips-dataplane-2026-06-08-docker.md`
- Latest exact short local-FIPS Docker perf smoke is nvpn `42f13785` plus FIPS
  `12c775a`; it passed all four phases, including the worker-pressure guard
  with explicit queue-full/bulk-drop counters and no tunnel-ping loss. See the
  checkpoint summaries above for hashes and phase numbers.
- Earlier short local-FIPS Docker perf and platform-matrix smokes for FIPS
  `27d1739` plus nvpn `b620ff56` passed with direct underlay byte-counter
  progress in every phase. The platform matrix covers connected UDP on/off,
  single encrypt worker, and tight backpressure; pending-session drop counters
  stayed absent, while expected bulk queue-pressure events remained explicit.
- FIPS `df6ee3d` adds a deterministic single-flow encrypt-worker ordering
  guard to the default Linux safety runner. It is test/script-only, so the
  current runtime perf and platform-matrix baseline remains the FIPS `27d1739`
  run above.
- FIPS `ce651a7` names the encrypt-worker send-target key used by macOS sender
  selection and batch grouping. The short local-FIPS Docker perf smoke against
  nvpn `810a84cd` passed all four phases with direct byte-counter progress and
  no TCP/ping wedge.
- FIPS `1cabfce` extends that exact send-target key to non-macOS worker
  selection and fair-admission pressure accounting. The default Linux safety
  runner now includes `fair_admission_keys_pressure_by_exact_send_target`, and a
  short local-FIPS Docker perf smoke against nvpn `cdf6e0d6` passed all four
  phases.
- FIPS `cbd9e4d` lets non-macOS encrypt priority jobs bypass the bulk
  per-target fair-admission cap while still staying bounded by the worker
  channel. The default Linux safety runner now includes
  `priority_flow_enters_when_bulk_flow_reaches_per_flow_cap`, and a short
  local-FIPS Docker perf smoke against nvpn `65cbe34e` passed all four phases.
  The current platform matrix against nvpn `3eda64fd` passed
  `connected-udp-on`, `single-encrypt-worker`, and `tight-backpressure`; the
  first `connected-udp-off` run failed one constrained reverse-load ping window
  at `5%` loss against a `2%` ceiling, then a same-knob targeted rerun passed.
- FIPS `3c3995e` adds a fresh-bogus MMP parent-choice guard. The default Linux
  safety runner now includes
  `test_parent_reeval_ignores_fresh_bogus_metrics_without_valid_rtt`, proving
  severe fresh loss/goodput deltas without a valid RTT do not make an otherwise
  attractive candidate parent-eligible.
- FIPS `4ed5c02` pins healthy operator-configured static UDP peers to their
  direct route even when a learned fallback has lower MMP cost. The default Linux
  safety runner now includes direct-vs-fallback route sanity tests for stale,
  session-degraded, static-direct, and tree-fallback cases.
- FIPS `bbf72ff` names the decrypt-worker session owner key used at the worker
  boundary and in registered-session tracking. The default Linux safety runner
  now includes
  `decrypt_session_key_routes_registration_jobs_and_unregister_to_same_worker`,
  proving registration, priority packet jobs, and unregister for one FMP receive
  session hash to the same worker shard.
- FIPS `9865d3e` makes decrypt-worker unregister pressure visible and extends
  the Linux safety runner with
  `decrypt_worker_unregister_uses_priority_lane_when_bulk_queue_is_full` and
  `decrypt_worker_unregister_full_returns_false_without_waiting`, so teardown
  cannot silently block behind bulk or overflow the bounded priority lane.
- FIPS `a024fcb` adds
  `decrypt_worker_drain_unregisters_priority_before_bulk_jobs` to the Linux
  safety runner, proving queued unregister removes stale worker-owned session
  state before queued old-session bulk work can run.
- FIPS `7e5c03d` adds `send_backpressure` to the Linux safety runner, pinning
  the UDP send backpressure pacer decision rules for WouldBlock, ENOBUFS/ENOMEM,
  sleep throttling, and explicit bulk-drop budgets.
- FIPS `075a0cf` adds
  `pipelined_endpoint_wire_uses_reserved_counters_and_offsets` to the Linux
  safety runner, pinning the pipelined endpoint FMP/FSP header counters and
  worker FSP seal offsets before moving send-counter ownership.
- FIPS `1a93a16` adds
  `test_pipelined_send_counter_reservation_is_single_owner` to the Linux safety
  runner, proving cloned worker AEAD use does not mutate session-owned send
  counter sequencing.
- FIPS `461c17a` adds
  `decrypt_worker_accepts_fmp_replay_only_after_aead_success` to the Linux
  safety runner, proving the decrypt worker accepts FMP replay counters only
  after AEAD success and drops a repeated counter before emitting fallback work.
- The current local-FIPS Docker soak for FIPS `0e58727` plus nvpn `d9c24147`
  passed `33` samples over `30` minutes with direct Docker underlay paths, `0%`
  ping loss both ways, and no queue/drop/fallback hard events.
- The full default FIPS Linux deterministic runner passed at FIPS `1a93a16`
  with the current queue/backpressure, route, MMP, connected-UDP, and ownership
  guards in its default filter list.
- FIPS `95382b5` adds
  `decrypt_worker_fallback_priority_full_returns_false_without_waiting` to the
  Linux safety runner, proving decrypt-failure/control fallback pressure is
  visible and does not park the worker or spill into bulk capacity.
- FIPS `a1e6b13` adds
  `fallback_drain_prefers_ready_priority_over_selected_bulk` to the Linux safety
  runner, proving rx-loop fallback drains prefer newly ready priority work over
  a selected bulk fallback head.
- The full default FIPS Linux deterministic runner passed at FIPS `a1e6b13`
  with the newer decrypt fallback priority-pressure and rx-loop fallback
  priority-drain guards in its default filter list.
- FIPS `a1e6b13` plus nvpn `600a0ad3` passed a short local-FIPS Docker
  platform matrix covering `connected-udp-on`, `connected-udp-off`,
  `single-encrypt-worker`, and `tight-backpressure`. Direct counters advanced
  in every phase, expected explicit bulk pressure remained bounded, and no
  TCP/ping wedge appeared. This is local Docker platform-split evidence only,
  not host/VM soak or real Mac-to-Mac validation.
- FIPS `8db775f` adds a deterministic connected-UDP cap-tail guard. Once the
  explicit `max_peers` cap is exhausted, the activation tick records the
  current plus remaining skipped peers once and stops walking that candidate
  tail, leaving those peers on wildcard UDP instead of silently expanding the
  one-drain-thread-per-peer fast path.
- The full default FIPS Linux deterministic runner passed at FIPS `8db775f`
  with the connected-UDP cap-tail tests included under the default
  `connected_udp` filter.
- FIPS `8db775f` plus nvpn `9810c53b` passed a short local-FIPS Docker soak
  smoke with the hardened parser path active. It recorded two samples on the
  configured direct Docker underlay, `0%` ping loss both ways, no hard
  queue/drop/backpressure events, and bounded FIPS/nvpn queue-wait p99 values.
  This is parser/runtime smoke evidence only, not a 30-60 minute soak.
- FIPS `1a77baf` adds
  `endpoint_command_tx_helper_classifies_priority_and_bulk_payloads` to the
  default Linux safety runner, so the endpoint command sender helper is now
  run alongside the lower-level endpoint traffic classifier. This pins the
  reserved endpoint priority command lane for ACK/control-shaped payloads and
  the bounded bulk command lane for large endpoint payloads before later
  endpoint/shard ownership work.
- The full default FIPS Linux deterministic runner passed at FIPS `1a77baf`
  with the endpoint command lane helper included in the default filter list,
  alongside the current queue/backpressure, route, MMP, connected-UDP,
  ownership, fallback, and pending-session guards.
- FIPS `1a77baf` plus nvpn `518245f9` then ran the default-duration
  local-FIPS Docker platform matrix. `connected-udp-on`, `connected-udp-off`,
  and `single-encrypt-worker` passed, but `tight-backpressure` failed during
  clean-underlay reverse TCP at `88.7 Mbps` against the `100 Mbps` floor while
  explicit decrypt bulk/fallback bulk drops were visible. Treat this as a
  current pre-refactor safety-net failure to preserve and improve, not as a
  green platform-matrix baseline. A targeted `tight-backpressure` rerun at nvpn
  `d5a734fc` also failed in clean-underlay, this time after initial reverse TCP
  passed, when reverse TCP under load fell to `75.3 Mbps` against the same
  floor.
- FIPS `33f840e` splits the decrypt worker input cap from the decrypt
  worker-to-rx-loop fallback bulk cap. The shared `FIPS_WORKER_CHANNEL_CAP`
  still forces explicit worker bulk drops, but no longer also shrinks the
  fallback return lane unless `FIPS_DECRYPT_FALLBACK_CHANNEL_CAP` is set. The
  targeted local-FIPS Docker `tight-backpressure` rerun against nvpn `d9803083`
  passed all four phases with direct byte-counter progress, `0%` ping loss, and
  no fallback-bulk drops in the captured phase summaries.
- The full default FIPS Linux deterministic runner passed again at FIPS
  `33f840e` with the fallback-cap split guard in the default filter list.
- FIPS `33f840e` plus nvpn `2130027a` then ran the full local-FIPS Docker
  platform matrix. `connected-udp-on`, `connected-udp-off`, and
  `single-encrypt-worker` passed with direct byte-counter progress and `0%`
  ping loss in their load phases, but `tight-backpressure` failed immediately
  during clean-underlay forward TCP at `75.0 Mbps` against the `100 Mbps`
  floor. The saved logs still show expected decrypt-worker bulk drops and no
  `decrypt_fallback_bulk_dropped` events. Treat this as a remaining
  matrix/order-sensitive red target, not as a green broad platform baseline.
- FIPS `33f840e` plus nvpn `0c498368` reproduced a narrower order-sensitive
  red case with the failure-summary harness active. Running
  `single-encrypt-worker,tight-backpressure` passed the first scenario, then
  `tight-backpressure` passed clean, constrained, and worker-pressure phases
  before failing `rx-maintenance-fault` forward TCP at `17.1 Mbps` against the
  `100 Mbps` floor. The new `failure-summary.tsv` captured the exact failed
  metric and threshold, direct byte counters advanced in completed phases, and
  `decrypt_fallback_bulk_dropped` did not appear in the logs. Treat this as the
  current sharper pre-refactor red target: tight worker/send backpressure plus
  rx-loop maintenance delay must degrade recoverably instead of collapsing.
- The perf and platform-matrix harnesses now accept a phase selector for
  targeted red-case probes: `NVPN_PERF_PHASES` on the perf gate and
  `NVPN_PLATFORM_MATRIX_PHASES` on the matrix wrapper. A follow-up local-FIPS
  Docker probe after nvpn `ae422764` used
  `NVPN_PLATFORM_MATRIX_PHASES=clean-underlay,rx-maintenance-fault` with only
  the `tight-backpressure` scenario. It failed before a completed phase row,
  and `failure-summary.tsv` captured clean-underlay forward TCP at
  `87.9 Mbps` against the `100 Mbps` floor. Treat this as complementary to the
  rx-maintenance-collapse artifact: the tight backpressure profile can still
  trip the clean-underlay floor under targeted runs, while the previous order
  probe preserves the sharper rx-maintenance collapse.
- FIPS `33f840e` plus nvpn `80c404f5` then ran the richer failed-phase context
  harness against the tight-profile probes. An isolated
  `tight-backpressure`/`rx-maintenance-fault` phase passed, which suggests the
  old rx-maintenance collapse is not just a fresh-start rx fault. The longer
  `single-encrypt-worker,tight-backpressure` order probe reproduced a current
  red case: `single-encrypt-worker` passed all phases, then
  `tight-backpressure` failed clean-underlay forward TCP at `92.2 Mbps` against
  the `100 Mbps` floor. The 21-field `failure-summary.tsv` preserved phase,
  step, retransmits, direct-byte deltas, and pipeline context; the log/artifact
  scan showed `decrypt_worker_queue_full` / `decrypt_worker_bulk_dropped` and
  no `decrypt_fallback_bulk_dropped`. Keep this as the current concrete
  pre-refactor target.
- The platform matrix now exposes `tight-send-backpressure` separately from
  `tight-backpressure`. A follow-up focused probe showed that raising only
  decrypt-worker admission to `8` still failed clean-underlay forward TCP at
  `27.5 Mbps` with decrypt bulk drops visible. Restoring decrypt admission to
  `32768` moved the failure to the send side: clean forward/reverse TCP passed,
  but the concurrent load leg failed at `93.4 Mbps` with
  `encrypt_worker_queue_full` / `encrypt_worker_bulk_dropped` visible. Keep the
  isolated `tight-send-backpressure` scenario red until TCP degrades
  recoverably under send pressure.
- The full local-FIPS matrix at FIPS `682ba9f` plus nvpn `50e7361e` passed
  `connected-udp-on`, `connected-udp-off`, and `single-encrypt-worker`, but
  kept `tight-send-backpressure` red on clean-underlay reverse-load ping loss
  and `tight-backpressure` red on clean-underlay forward TCP. FIPS `bc000de`
  then made Linux batched sends honor the explicit UDP bulk-drop budget without
  changing the default Linux retry-only budget (`0`).
- A focused `tight-send-backpressure` clean-underlay run with
  `FIPS_SEND_BACKPRESSURE_DROP_AFTER=2` at FIPS `bc000de` plus nvpn `8eb1ee74`
  still failed on reverse-load ping loss (`5%` against `2%`). The captured
  context showed encrypt-worker queue-full/bulk-drop pressure, not
  `udp_send_bulk_dropped`, so the next incremental target remains worker
  admission/drain.
- FIPS `e1c67a7` decouples the non-macOS encrypt priority reserve from the
  tight bulk worker channel cap and adds
  `priority_reserve_does_not_shrink_with_tight_bulk_channel_cap` to the default
  Linux deterministic runner. A focused `tight-send-backpressure`
  clean-underlay rerun against nvpn `ac679170` still failed reverse-load ping
  loss (`5%` against `2%`), but the warning pattern no longer pointed at a
  priority reserve shortage and `udp_send_bulk_dropped` stayed absent. The
  remaining red signal is bulk encrypt-worker pressure plus one lost tunnel ping
  under concurrent load.
- nvpn `805b2ff` aligns the matrix default ping count with the perf gate
  default (`60`) and pins that default plus the override in
  `test-fips-platform-matrix-harness.sh`. The focused
  `tight-send-backpressure` clean-underlay rerun at FIPS `e1c67a7` then passed:
  one forward-load ping was lost (`1.66667%`, within the `2%` ceiling),
  reverse-load and post-load ping loss were `0%`, TCP stayed above floor, direct
  bytes advanced, and expected encrypt bulk drops remained visible. Treat this
  as clearing the short-sample send-pressure red artifact, not as a substitute
  for the full matrix or host/VM soak.
- FIPS `ae874b2` makes IPv4 ICMP tunnel-ping payloads priority/non-droppable,
  matching the existing ICMPv6 and small-control classifier policy. The
  deterministic classifier tests, focused Linux safety runner slice, and full
  Linux safety runner passed. A focused `tight-send-backpressure` platform
  matrix at FIPS `ae874b2` plus nvpn `02a1ae2` also passed all phases, including
  the former `rx-maintenance-fault` ping-loss row; tunnel ping loss was `0%` in
  all load/post windows and expected encrypt bulk pressure remained visible.
- The full platform matrix at those same heads remains red in a more useful
  place: `connected-udp-on`, `connected-udp-off`, and `single-encrypt-worker`
  passed, but `tight-send-backpressure` failed clean-underlay forward TCP at
  `93.3 Mbps` against the `100 Mbps` floor and `tight-backpressure` failed
  clean-underlay forward TCP at `11.7 Mbps`. Keep this as the current
  Linux/docker safety target: TCP must degrade recoverably under explicit
  bounded worker/send pressure before moving hot-path ownership.
- FIPS `24bff11` bounds the non-macOS encrypt-worker fast lane to one per-flow
  burst plus fair budget and adds
  `tight_bulk_cap_limits_single_flow_to_fast_lane_plus_fair_budget` to the
  default Linux safety runner. The focused Linux fair-queue slice, `cargo
  fmt --check`, and full Linux deterministic runner passed.
- A focused local-FIPS platform matrix at FIPS `24bff11` plus nvpn `4073298`
  passed both known tight-pressure rows. `tight-send-backpressure` passed all
  phases with clean-underlay forward/reverse TCP at `321.8` / `310.9 Mbps`;
  `tight-backpressure` passed all phases with clean-underlay forward/reverse TCP
  at `136.2` / `116.2 Mbps`. Both rows kept load/post tunnel-ping loss at `0%`
  while the expected encrypt/decrypt queue-full and bulk-drop pressure stayed
  visible. This clears the focused red target, but it does not replace a full
  default platform matrix, Docker soak, host/VM soak, or real Mac-to-Mac
  validation.
- The full default local-FIPS platform matrix at the same heads then passed
  `connected-udp-on`, `connected-udp-off`, `single-encrypt-worker`, and
  `tight-send-backpressure`, but remained red on `tight-backpressure` during
  `rx-maintenance-fault`: reverse TCP reached `98.9 Mbps` against the
  `100 Mbps` floor. This is narrower than the earlier full-matrix failures and
  no longer looks like ping starvation, but it still blocks broad refactor
  clearance until a focused rerun or code change removes the miss and the full
  matrix goes green.
- A focused `tight-backpressure`/`rx-maintenance-fault` rerun at FIPS
  `24bff11` plus nvpn `81359bf` passed, then a three-attempt
  `tight-backpressure` scenario rerun passed all attempts and all phases. The
  full default local-FIPS matrix rerun at the same heads then passed all five
  scenarios. The tight combined row remains the lowest-headroom matrix case,
  but the current Linux/docker matrix gate is green. A current 30-minute Docker
  soak at FIPS `24bff11` plus nvpn `a9bfbcd` also passed with direct path
  stable, `0%` tunnel-ping loss, bounded SRTT, and no hard queue/drop events.
  This is enough local Docker evidence to begin the first small
  ownership-moving refactor behind existing APIs. Host/VM soak and real
  Mac-to-Mac soak remain separate validation, not coverage implied by Docker.
- FIPS `cda112a` takes that first small step by wrapping the decrypt worker's
  existing session table in an explicit `DecryptWorkerShard` owner. The new
  `decrypt_worker_shard_owns_register_and_unregister_state` guard is in the
  default Linux deterministic runner. `cargo fmt --check`, focused
  `cargo test -p fips-core decrypt_worker -- --nocapture`, the full default
  Linux deterministic runner, and a short local-FIPS Docker perf smoke against
  nvpn `85be91d` all passed. The smoke kept direct byte progress and `0%`
  load/post tunnel-ping loss in all phases.
- FIPS `c33996e` makes FMP worker-send counter ownership explicit for the
  established send path. `FmpWorkerSendReservation` owns the cloned cipher,
  reserved counter, and header together, and the send path resolves the worker
  UDP target before consuming a counter. The new guards
  `fmp_worker_send_reservation_owns_counter_header_and_cipher` and
  `fmp_worker_target_fallback_consumes_one_inline_counter` are in the default
  Linux deterministic runner; focused local and Linux-container runs passed.
  Full local `cargo test -p fips-core` also passed, and a short local-FIPS
  Docker perf smoke against nvpn `de4342ac` kept all four phases green with
  direct byte progress and `0%` load/post tunnel-ping loss.
- FIPS `b02eb10` makes FMP worker-recv open/replay ownership explicit for the
  established receive path. `OwnedSessionState::open_fmp_in_place` owns replay
  check, AEAD open, and replay accept together. The new
  `owned_session_state_open_fmp_owns_replay_acceptance` guard is in the default
  Linux deterministic runner. `cargo fmt --check`, focused local/container
  replay guards, full local `cargo test -p fips-core`, the full default Linux
  deterministic runner, and a short local-FIPS Docker perf smoke against nvpn
  `03f96c48` all passed. The smoke kept direct byte progress and `0%`
  load/post tunnel-ping loss in all phases.
- FIPS `a93cd50` makes FSP recv open/replay ownership explicit for the
  established session path. `SessionEntry::open_fsp_established_frame` owns
  current/pending/previous epoch selection plus replay check, AEAD open, and
  replay accept. The new
  `open_fsp_established_frame_failed_all_epochs_does_not_consume_replay` guard
  is in the default Linux deterministic runner. `cargo fmt --check`, focused
  local epoch tests, full local `cargo test -p fips-core`, the full default
  Linux deterministic runner, and a short local-FIPS Docker perf smoke against
  nvpn `201d3c97` all passed. The smoke kept direct byte progress and `0%`
  load/post tunnel-ping loss in all phases.
- FIPS `4fa502b` makes FSP worker-send reservation ownership explicit for the
  established endpoint-data path. `FspSendReservation` owns the cloned cipher,
  reserved FSP counter, and header together before worker sealing. The new
  `reserve_fsp_worker_send_owns_counter_header_and_cipher` guard is in the
  default Linux deterministic runner. `cargo fmt --check`, focused local and
  Linux-container send guards, full local `cargo test -p fips-core`, the full
  default Linux deterministic runner, and a short local-FIPS Docker perf smoke
  against nvpn `f330cfe9` all passed. The smoke kept direct byte progress and
  `0%` load/post tunnel-ping loss in all phases.
- FIPS `c4c3895` makes selected send-target ownership explicit for FMP worker
  jobs. `SelectedSendTarget` carries the UDP socket, optional connected socket,
  destination sockaddr, and computed target key through dispatch, fair
  admission, macOS ordered flow selection, and flush grouping. The new
  `selected_send_target_key_drives_dispatch_and_admission` guard is in the
  default Linux deterministic runner. `cargo fmt --check`, focused local unix
  send-path coverage, focused Linux-container target/admission/dispatch/batch
  guards, full local `cargo test -p fips-core`, the full default Linux
  deterministic runner, and a short local-FIPS Docker perf smoke against nvpn
  `dd866d34` all passed. The smoke kept direct byte progress and `0%`
  load/post tunnel-ping loss in all phases.
- FIPS `480b549` makes selected send-batch ownership explicit for Unix batch
  flush. Each group now owns one selected target, FIFO wire-packet list, and
  aggregate drop-on-backpressure policy. The new
  `selected_send_batch_owns_target_fifo_and_drop_policy` guard is in the
  default Linux deterministic runner. `cargo fmt --check`, focused local and
  Linux-container send-path guards, full local `cargo test -p fips-core`, the
  full default Linux deterministic runner, and a short local-FIPS Docker perf
  smoke against nvpn `e4e86055` all passed. The smoke kept direct byte progress
  and `0%` load/post tunnel-ping loss in all phases.
- FIPS `3bb9d64` makes Linux send-attempt ownership explicit for the batched
  Unix send path. `LinuxSendBatchAttempt` owns the selected target, remaining
  packet cursor, send backpressure pacer, and current-packet drop decision. The
  new `linux_send_batch_attempt_owns_cursor_and_backpressure_policy` guard is
  in the default Linux deterministic runner. `cargo fmt --check`, focused
  local and Linux-container send-path guards, full local
  `cargo test -p fips-core`, the full default Linux deterministic runner, and
  a short local-FIPS Docker perf smoke against nvpn `7d29592f` all passed. The
  smoke kept direct byte progress and `0%` load/post tunnel-ping loss in all
  phases.
- FIPS `40ce258` makes non-Linux direct-send attempt ownership explicit for
  the macOS/BSD direct sender path. `DirectSendBatchAttempt` owns the selected
  target, remaining packet cursor, send backpressure pacer, and current-packet
  drop decision. The new
  `direct_send_batch_attempt_owns_cursor_and_backpressure_policy` guard is in
  the local macOS queue test suite. `cargo fmt --check`, focused local
  direct-send/backpressure guards, local `mac_queue_tests`, focused
  Linux-container send-path guards, full local `cargo test -p fips-core`,
  `cargo check -p fips-core --release`, and a short local-FIPS Docker
  no-regression smoke against nvpn `589a8cf6` all passed. The Docker smoke kept
  direct byte progress and `0%` load/post tunnel-ping loss in all phases, but
  does not exercise the non-Linux direct sender.
- FIPS `cb3640d` makes non-macOS fair-admission reservation ownership explicit.
  `FairAdmissionReservation` owns the selected send target key from reserve
  through enqueue/drain or enqueue failure, and release consumes the token
  instead of recomputing flow identity later. The new
  `fair_admission_reservation_owns_release_key` guard is in the default Linux
  deterministic runner. `cargo fmt --check`, focused Linux-container
  reservation/target/priority guards, full local `cargo test -p fips-core`,
  `cargo check -p fips-core --release`, the full default Linux deterministic
  runner, and a short local-FIPS Docker smoke against nvpn `1ad2ab8e` all
  passed. The smoke kept direct byte progress and `0%` load/post tunnel-ping
  loss in all phases, with expected worker-pressure queue-full/bulk-drop
  counters.
- FIPS `7fad0e4` makes encrypt-worker shard batch ownership explicit.
  `EncryptWorkerShard` owns the reusable worker-local batch vector and the
  drain/flush cycle for both Linux and macOS worker loops. The new
  `encrypt_worker_shard_owns_batch_drain_and_flush_error` guard is in the
  default Linux deterministic runner. `cargo fmt --check`, focused local shard
  and macOS queue coverage, focused Linux-container shard/dispatch/batch/send
  guards, full local `cargo test -p fips-core`, `cargo check -p fips-core
  --release`, the full default Linux deterministic runner, and a short
  local-FIPS Docker smoke against nvpn `aa84aa32` all passed. The smoke kept
  direct byte progress and `0%` load/post tunnel-ping loss in all phases, with
  expected worker-pressure queue-full/bulk-drop counters.
- FIPS `7a9b3de5` makes sealed send-packet ownership explicit inside the
  encrypt worker. `SealedSendPacket` owns the selected send target, final
  sealed wire packet, and drop-on-backpressure policy after optional FSP seal
  plus outer FMP seal. The new
  `sealed_send_packet_owns_target_wire_and_drop_policy` guard is in the
  default Linux deterministic runner. `cargo fmt --check`, focused local
  sealed-packet/shard coverage, focused Linux-container send-path guards, local
  `mac_queue_tests`, full local `cargo test -p fips-core`, `cargo check -p
  fips-core --release`, the full default Linux deterministic runner, and a
  short local-FIPS Docker smoke against nvpn `e93b94d9` all passed. The smoke
  kept direct byte progress and `0%` load/post tunnel-ping loss in all phases,
  with expected worker-pressure queue-full/bulk-drop counters.
- FIPS `8792215a` makes queued encrypt-worker message ownership explicit.
  `QueuedFmpSendJob` owns the priority/bulk lane and selected send-target key
  captured at queue-message construction time. The new
  `queued_fmp_send_job_owns_lane_and_target_key` guard is in the default Linux
  deterministic runner. `cargo fmt --check`, focused local queued-message,
  sealed-packet, and shard coverage, focused Linux-container send/admission
  guards, local `mac_queue_tests`, full local `cargo test -p fips-core`,
  `cargo check -p fips-core --release`, the full default Linux deterministic
  runner, and a short local-FIPS Docker smoke against nvpn `61d4ad10` all
  passed. The smoke kept direct byte progress and `0%` load/post tunnel-ping
  loss in all phases, with expected worker-pressure queue-full/bulk-drop
  counters.
- FIPS `e2254b8` carries the queued target key through the seal-to-batch
  handoff. `SealedSendPacket` owns the queued target key as well as the
  selected target, final wire packet, and drop policy, and `SelectedSendBatch`
  groups with that handed-off key. The new
  `queued_target_key_survives_seal_and_batch_grouping` guard is in the default
  Linux deterministic runner. `cargo fmt --check`, focused local queued-key and
  sealed-packet guards, local `mac_queue_tests`, `cargo check -p fips-core
  --release`, and a focused Linux-container queued-key/seal/batch/send/no-wedge
  slice passed after the helper cleanup. Full local `cargo test -p fips-core`
  passed before that cleanup. No new nvpn perf smoke was run because this step
  does not change queue, routing, or send-policy behavior.
- FIPS `758f3bb` adds `scripts/test-dataplane-ownership-fast.sh`, the focused
  tier for pure ownership/type-boundary changes. The default run passed:
  formatting, focused local ownership tests, local `mac_queue_tests`,
  `cargo check -p fips-core --release`, and the focused Linux Docker ownership
  slice. Use the full deterministic runner, perf matrix, or soak only when the
  change touches their behavior surface or when making a broad gate claim.
- FIPS `95bc769` makes queued send scheduling-weight ownership explicit.
  `QueuedFmpSendJob` snapshots the clamped non-macOS fair-admission weight at
  construction time, and fair admission reads that queued-message value. The
  new `queued_fmp_send_job_owns_clamped_scheduling_weight` guard is in the
  default Linux deterministic runner and fast ownership tier. The fast
  ownership tier passed; no nvpn perf smoke was run because this does not alter
  queue, route, or send-policy behavior.
- FIPS `fa80ef4` makes queued decrypt-job lane ownership explicit. `DecryptJob`
  snapshots the priority/bulk lane when rx loop builds the worker message, and
  dispatch reads that queued value. The new
  `decrypt_job_owns_lane_selected_at_construction` guard is in the default
  Linux deterministic runner and fast ownership tier. The fast ownership tier
  passed; no nvpn perf smoke was run because this does not alter queue, route,
  or send-policy behavior.
- FIPS `7bdf1e1` makes decrypt fallback event lane ownership explicit.
  `DecryptFallback` snapshots the priority/bulk lane when the worker creates
  the rx-loop fallback event, and fallback enqueue reads that queued value. The
  new `decrypt_fallback_event_owns_lane_selected_at_construction` guard is in
  the default Linux deterministic runner and fast ownership tier. The fast
  ownership tier passed; no nvpn perf smoke was run because this does not alter
  queue, route, or send-policy behavior.
- FIPS `1da4102` makes macOS ordered-sender completion ownership explicit.
  `MacCompletionGroup` snapshots the selected flow key and consumes itself when
  completing FIFO items to the owning send flow. The new
  `mac_completion_group_owns_flow_key_and_fifo_items` guard is in the local side
  of the fast ownership tier. The fast ownership tier passed; this is macOS
  unit/logic coverage only, not real Mac-to-Mac validation.
- FIPS `f908f32` starts the measured rewrite phase with an rx-loop drain cursor.
  `PriorityBulkDrainCursor` owns the selected priority/bulk head item and the
  remaining bounded drain budget for endpoint commands and decrypt-worker
  fallback events. The new
  `priority_bulk_drain_cursor_owns_selected_head_and_budget` guard is in the
  fast ownership tier and Linux Docker safety runner. The focused guard passed
  locally, through release compile, and in Linux Docker. A focused Docker perf
  smoke with local-FIPS patching also passed `worker-queue-pressure` and
  `rx-maintenance-fault`, with `0%` concurrent ping loss in both phases and
  direct underlay byte progress on both nodes. This is Linux/Docker
  no-regression evidence, not real Mac-to-Mac validation.
- FIPS `853a2fe` makes the raw packet receiver-drain boundary explicit.
  `PacketDrainCursor` owns the selected first packet, remaining bounded packet
  budget, and fallback interleave point before rx-loop packet processing or
  fallback draining. The new
  `packet_drain_cursor_owns_first_packet_budget_and_interleave` guard is in the
  fast ownership tier and Linux Docker safety runner. The focused guard passed
  locally, through release compile, and in Linux Docker. A focused Docker perf
  smoke with local-FIPS patching also passed `worker-queue-pressure` and
  `rx-maintenance-fault`, with `0%` concurrent ping loss in both phases and
  direct underlay byte progress on both nodes. This is Linux/Docker
  no-regression evidence, not real Mac-to-Mac validation.
- FIPS `4d321ed` makes the TUN outbound receiver-drain boundary explicit.
  `TunOutboundDrainCursor` owns the selected first TUN packet and remaining
  bounded packet budget before endpoint send. The new
  `tun_outbound_drain_cursor_owns_first_packet_and_budget` guard is in the fast
  ownership tier and Linux Docker safety runner. The focused guard passed
  locally, through release compile, and in Linux Docker. A focused Docker perf
  smoke with local-FIPS patching also passed `worker-queue-pressure` and
  `rx-maintenance-fault`, with `0%` concurrent ping loss in both phases and
  direct underlay byte progress on both nodes. This is Linux/Docker
  no-regression evidence, not real Mac-to-Mac validation.
- FIPS `e637420` makes the rx-loop data-drain result explicit.
  `RxLoopDataDrainStats` owns packet, TUN, and endpoint drain counts, the total
  drained value, and the data-pressure decision used by maintenance. The new
  `rx_loop_data_drain_stats_owns_counts_total_and_pressure` guard is in the
  fast ownership tier and Linux Docker safety runner. The focused guard passed
  locally, through release compile, and in Linux Docker. A focused Docker perf
  smoke with local-FIPS patching first caught an intermittent
  `rx-maintenance-fault` forward-load ping p99 miss at `252 ms` with `0%` loss
  and direct underlay byte progress; an immediate rerun passed
  `worker-queue-pressure` and `rx-maintenance-fault`, with `0%` concurrent ping
  loss in both phases and direct underlay byte progress on both nodes. Treat the
  first red row as a maintenance-tail watch item, not a deterministic
  regression. This is Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `8a23f25` makes the rx-loop maintenance state explicit.
  `RxLoopMaintenanceState` owns recent data activity and the sticky
  slow-maintenance timeout flag used by the data-pressure and skip-slow
  decisions. The new
  `rx_loop_maintenance_state_owns_activity_window_and_timeout_skip` guard is in
  the fast ownership tier and Linux Docker safety runner. The focused guard
  passed locally, through release compile, and in Linux Docker. A focused Docker
  perf smoke with local-FIPS patching passed `worker-queue-pressure` and
  `rx-maintenance-fault`, with `0%` concurrent ping loss in both phases and
  direct underlay byte progress on both nodes. This is Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `cb953f0` makes the rx-loop maintenance plan explicit.
  `RxLoopMaintenancePlan` owns the data-pressure bit, skip-slow decision, and
  selected idle/busy slow-maintenance timeout consumed by the maintenance tick.
  The new
  `rx_loop_maintenance_plan_owns_pressure_skip_and_timeout_budget` guard is in
  the fast ownership tier and Linux Docker safety runner. The focused guard
  passed locally, through release compile, and in Linux Docker. No perf smoke
  was run for this ownership-only slice because no queue, route, timeout, or
  send-policy threshold changed. This is Linux/Docker logic coverage, not real
  Mac-to-Mac validation.
- FIPS `f17ab93` gates full-mode session-layer MMP route changes on valid
  route-quality evidence. Fresh accepted loss/goodput deltas without a valid
  RTT no longer mark a direct session path degraded, schedule direct reprobe,
  start fallback discovery, or move payload routing to learned fallback. The new
  `test_fresh_bogus_session_metrics_without_valid_rtt_do_not_change_route_choice`
  guard is in the Linux Docker safety runner, while the existing valid-loss
  degradation guard now proves full-mode route changes have a valid RTT sample.
  Verification passed locally and in the focused Linux Docker slice. This is
  deterministic route/MMP policy coverage, not real Mac-to-Mac validation.
- FIPS `470becb` makes outbound endpoint command lane ownership explicit.
  `NodeEndpointCommand::Send` and `SendOneway` now snapshot the priority/bulk
  lane at construction, and `FipsEndpoint` selects the priority or bulk command
  channel from that queued lane. The new
  `endpoint_command_owns_lane_selected_at_construction` guard is in the fast
  ownership tier and Linux Docker safety runner. The guard failed first against
  the old shape, then passed locally and in Linux Docker; the full default fast
  ownership tier passed. No perf smoke was run because this does not alter queue
  capacity, route choice, timeout policy, send backpressure thresholds, or Mac
  sender behavior.
- FIPS `4a3d2d8` makes outbound endpoint send command ownership explicit.
  `EndpointSendCommand` owns the remote peer identity, payload, selected lane,
  and queue timestamp shared by `Send` and `SendOneway`, and the rx-loop command
  handler consumes that one owner through a shared send path. The new
  `endpoint_send_command_owns_payload_lane_and_queue_stamp` guard is in the fast
  ownership tier and Linux Docker safety runner. The guard failed first against
  the old duplicated enum fields, then passed locally and in Linux Docker; the
  full default fast ownership tier passed. No perf smoke was run because this
  does not alter queue capacity, route choice, timeout policy, send backpressure
  thresholds, or Mac sender behavior.
- FIPS `129543f` makes endpoint payload policy ownership explicit.
  `EndpointDataPayload` owns endpoint app payload bytes as bulk/drop-on-pressure
  data. `EndpointSendCommand`, pending endpoint queues, and the pipelined send
  path now consume that owner instead of reclassifying raw payload bytes later. The new
  `endpoint_data_payload_owns_drop_policy_selected_at_construction` guard is in
  the fast ownership tier and Linux Docker safety runner. The guard failed
  first because the owner did not exist, then passed locally and in Linux
  Docker; the full default fast ownership tier passed on the final tree. No
  perf smoke was run because this is an ownership/type-boundary slice, not a
  queue capacity, route choice, timeout policy, send backpressure threshold, or
  Mac sender behavior change.
- FIPS `36b365b` makes endpoint data send ownership explicit.
  `EndpointDataSend` owns the destination node address, destination public key,
  and endpoint payload owner. `EndpointSendCommand` carries that
  owner, and the rx-loop send-or-queue path consumes it when registering
  identity, sending immediately, or queueing for session recovery. The new
  `endpoint_data_send_owns_remote_identity_and_payload_policy` guard is in the
  fast ownership tier and Linux Docker safety runner. The guard failed first
  because the owner did not exist, then passed locally and in Linux Docker; the
  full default fast ownership tier passed. No perf smoke was run because this
  is an ownership/type-boundary slice, not a queue capacity, route choice,
  timeout policy, send backpressure threshold, or Mac sender behavior change.
- FIPS `662f0dc` makes the pending endpoint data queue explicit.
  `PendingEndpointDataQueue` owns the per-destination endpoint payload backlog
  and its bounded drop-oldest admission result. The node still owns the
  destination map and existing configured caps, but it consumes the queue
  admission result instead of open-coding the `VecDeque` drop policy. The new
  `pending_endpoint_data_queue_owns_drop_oldest_policy` guard is in the fast
  ownership tier and Linux Docker safety runner. The guard failed first because
  the owner did not exist, then passed locally and in Linux Docker; the full
  default fast ownership tier passed. No perf smoke was run because this is an
  ownership/type-boundary slice, not a queue capacity, route choice, timeout
  policy, send backpressure threshold, or Mac sender behavior change.
- FIPS `95ace56` makes the pending TUN packet queue explicit.
  `PendingTunPacketQueue` owns the per-destination TUN packet backlog and its
  bounded drop-oldest admission result. The node still owns the destination map
  and existing configured caps, but it consumes the queue admission result
  instead of open-coding the `VecDeque` drop policy. The new
  `pending_tun_packet_queue_owns_drop_oldest_policy` guard is in the fast
  ownership tier and Linux Docker safety runner. The guard failed first because
  the owner did not exist, then passed locally and in Linux Docker; the full
  default fast ownership tier passed. No perf smoke was run because this is an
  ownership/type-boundary slice, not a queue capacity, route choice, timeout
  policy, send backpressure threshold, or Mac sender behavior change.
- FIPS `a2371b6` makes the combined pending session traffic queues explicit.
  `PendingSessionTrafficQueues` owns the TUN and endpoint backlog maps,
  destination-cap admission, per-destination bounded enqueue delegation, and
  destination cleanup. The node still consumes the same configured caps and
  records the same perf counters, but callers no longer mutate the two maps
  directly. The new
  `pending_session_traffic_queues_own_destination_admission` guard is in the
  fast ownership tier and Linux Docker safety runner. The guard failed first
  because the owner did not exist, then passed locally and in Linux Docker; the
  focused pending-session, discovery-timeout, and direct-link teardown tests
  passed; the full default fast ownership tier passed. No perf smoke was run
  because this is an ownership/type-boundary slice, not a queue capacity, route
  choice, timeout policy, send backpressure threshold, or Mac sender behavior
  change.
- FIPS `6a0c304` makes pending discovery lookup admission explicit.
  `PendingDiscoveryLookups` owns in-flight lookup dedupe and queue-full
  admission before route-repair lookups start. The existing backoff, bloom
  reachability, retry, and timeout behavior stays in place, but callers no
  longer open-code the pending lookup map's admission rules. The new
  `pending_discovery_lookup_queue_owns_dedup_and_capacity` guard is in the fast
  ownership tier and Linux Docker safety runner. The guard failed first because
  the owner did not exist, then passed locally and in Linux Docker; the focused
  pending-lookup timeout and queued-TUN route-repair tests passed; the full
  default fast ownership tier passed. No perf smoke was run because this is an
  ownership/type-boundary slice, not a route-choice, timeout, queue capacity,
  send backpressure threshold, or Mac sender behavior change.
- FIPS `1a7c444` makes reverse-path discovery request caching explicit.
  `RecentDiscoveryRequests` owns request-id dedupe, cache capacity, expiry,
  reverse-hop retention, and one-shot response-forward claims for
  `LookupResponse` routing. The lookup request/response handlers keep the same
  stats, MTU folding, proof verification, and route caching behavior, but no
  longer open-code the recent-request map's admission or forwarded-response
  state. The new
  `recent_discovery_requests_own_reverse_path_dedup_capacity_and_expiry` guard
  is in the fast ownership tier and Linux Docker safety runner. The guard
  failed first because the owner did not exist, then passed locally and in
  Linux Docker; the focused request/response discovery and recent-request
  expiry tests passed; the full default fast ownership tier passed. No perf
  smoke was run because this is an ownership/type-boundary slice, not a route
  choice, timeout, queue capacity, send backpressure threshold, or Mac sender
  behavior change.
- FIPS `73e2315` makes pending route retry scheduling explicit.
  `PendingRouteRetries` owns the retry-entry map, expired-entry removal,
  deterministic due ordering, reconnect retry budget, and active direct-path
  refresh budget. `process_pending_retries` keeps the same reconnect, direct
  refresh, advert-stale, and local-route retry behavior, but no longer
  open-codes expired-entry removal or due-set sorting/budgeting in the
  maintenance tick. The new
  `pending_route_retries_own_expiry_due_order_and_budgets` guard is in the fast
  ownership tier and Linux Docker safety runner. The guard failed first because
  the owner did not exist, then passed locally and in Linux Docker; focused
  `retry`, `process_pending_retries`, `link_dead`, and `open_discovery` tests
  passed; the full default fast ownership tier passed. No perf smoke was run
  because this is an ownership/type-boundary slice, not a route-choice,
  timeout, queue capacity, send backpressure threshold, or Mac sender behavior
  change.
- FIPS `0cd30aa` makes local send failure liveness signals explicit.
  `LocalSendFailures` owns the per-peer local-route-failure timestamps,
  peer-scoped fast-dead timeout selection, success clearing, non-local error
  ignoring, and stale-signal expiry. `note_local_send_outcome`,
  `local_send_failure_dead_timeout_for_peer`, and
  `purge_expired_local_send_failures` keep the same public behavior, but no
  longer mutate or query a raw `HashMap` directly. The new
  `local_send_failures_own_peer_scoped_fast_dead_clear_and_expiry` guard is in
  the fast ownership tier and Linux Docker safety runner. The guard failed
  first because the owner did not exist, then passed locally and in Linux
  Docker; focused `local_send_failure` and unrelated-peer route-failure tests
  passed; the full default fast ownership tier passed. No perf smoke was run
  because this is an ownership/type-boundary slice, not a route-choice,
  timeout, queue capacity, send backpressure threshold, or Mac sender behavior
  change.
- FIPS `750b81f` makes session direct degradation state explicit.
  `SessionDirectDegradation` owns the per-destination degraded-until map, hold
  extension, expiry cleanup, and clear behavior used by direct payload
  blocking. `session_direct_path_is_degraded`,
  `mark_session_direct_path_degraded`, and
  `clear_session_direct_path_degraded` keep the same public behavior, but no
  longer mutate or query a raw `HashMap` directly. The new
  `session_direct_degradation_owns_hold_extension_expiry_and_clear` guard is in
  the fast ownership tier and Linux Docker safety runner. The guard failed
  first because the owner did not exist, then passed locally and in Linux
  Docker; focused `session_direct`, fresh-bogus session metrics, and session
  receiver-loss fallback tests passed; the full default fast ownership tier
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a route-choice, timeout, queue capacity, send backpressure
  threshold, or Mac sender behavior change.
- FIPS `24f2c5b` makes discovery fallback-transit eligibility explicit.
  `DiscoveryFallbackTransit` owns the peer block/unblock set plus the
  direct-target exception and bootstrap-transport exclusion used by
  reply-learned lookup fanout. `set_discovery_fallback_transit_allowed` and
  `should_use_reply_learned_lookup_fallback_peer` keep the same public
  behavior, but no longer expose or query a raw blocked-peer `HashSet`
  directly. The new
  `discovery_fallback_transit_owns_target_exception_block_and_bootstrap_policy`
  guard is in the fast ownership tier and Linux Docker safety runner. The guard
  failed first because the owner did not exist, then passed locally and in Linux
  Docker; focused open-discovery promotion and disabled-transit origin/forward
  fanout tests passed; the full default fast ownership tier passed. No perf
  smoke was run because this is an ownership/type-boundary slice, not a
  route-choice, timeout, queue capacity, send backpressure threshold, or Mac
  sender behavior change.
- FIPS `0f3de2b` makes learned-route fallback exploration pacing explicit.
  `LearnedRouteFallbackExploration` owns the selected-count interval gate,
  duplicate suppression, disabled-interval behavior, and cleanup when learned
  routes expire. `LearnedRouteTable::should_explore_fallback` and
  `purge_expired` keep the same public behavior, but no longer own or mutate a
  raw last-explored `HashMap` directly. The new
  `learned_route_fallback_exploration_owns_interval_dedup_and_expiry` guard is
  in the fast ownership tier and Linux Docker safety runner. The guard failed
  first because the owner did not exist, then passed locally and in Linux
  Docker; focused learned-route and reply-learned coordinate-exploration tests
  passed; the full default fast ownership tier passed. No perf smoke was run
  because this is an ownership/type-boundary slice, not a route-choice,
  timeout, queue capacity, send backpressure threshold, or Mac sender behavior
  change.
- FIPS `440cafe` makes bootstrap transport bookkeeping explicit.
  `BootstrapTransports` owns adopted bootstrap transport-id membership plus the
  originating peer npub used for protocol-mismatch cooldown. Adoption registers
  both together, cleanup removes both together, and callers no longer mutate a
  raw bootstrap transport `HashSet` plus npub `HashMap` separately. The new
  `bootstrap_transports_own_membership_peer_npub_and_cleanup` guard is in the
  fast ownership tier and Linux Docker safety runner. The guard failed first
  because the owner did not exist, then passed locally and in Linux Docker;
  focused `bootstrap` tests passed, covering adopted traversal cleanup,
  primary-path racing, protocol-mismatch cooldown filtering, and
  bootstrap-transit discovery fanout; the full default fast ownership tier
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a route-choice, timeout, queue capacity, send backpressure
  threshold, or Mac sender behavior change.
- FIPS `019d7fe` makes transport kernel-drop tracking explicit.
  `TransportDropTracker` owns per-transport cumulative drop samples,
  rising-edge congestion-event detection, current dropping state, and cleanup.
  `detect_congestion` and `sample_transport_congestion` keep the same behavior,
  but no longer inspect or mutate a raw drop-state map directly. The new
  `transport_drop_tracker_owns_rising_edge_state_and_cleanup` guard is in the
  fast ownership tier and Linux Docker safety runner. The guard failed first
  because the owner did not exist, then passed locally and in Linux Docker;
  focused forwarding tests passed; the full default fast ownership tier passed.
  No perf smoke was run because this is an ownership/observability boundary
  slice, not a route-choice, timeout, queue capacity, send backpressure
  threshold, or Mac sender behavior change.
- FIPS `e634608` makes pending outbound handshake dispatch explicit.
  `PendingOutboundHandshakes` owns msg2 lookup by exact `(transport_id,
  our_index)`, unique cross-transport index fallback for equivalent/adopted UDP
  replies, ambiguity rejection, and cleanup. `handle_msg2` keeps the same
  behavior, but no longer open-codes the fallback scan across a raw
  pending-outbound map. The new
  `pending_outbound_handshakes_own_msg2_index_matching_and_cleanup` guard is in
  the fast ownership tier and Linux Docker safety runner. The guard failed
  first because the owner did not exist, then passed locally and in Linux
  Docker; focused handshake and transport-id-changed msg2 tests passed; the full
  default fast ownership tier passed. No perf smoke was run because this is an
  ownership/dispatch boundary slice, not a route-choice, timeout, queue
  capacity, send backpressure threshold, throughput, or Mac sender behavior
  change.
- FIPS `400f7ec` makes active session-index dispatch explicit.
  `SessionIndexRegistry` owns active `(transport_id, our_index) -> NodeAddr`
  receiver-index lookup, stale-owner replacement, remove-return owner, and
  peer-has-other-index membership used by connected-UDP cleanup.
  `handle_encrypted_frame`, current-session registration repair, and
  deregistration keep the same behavior, but no longer inspect or mutate a raw
  receiver-index map directly. The new
  `session_index_registry_owns_lookup_replace_remove_and_peer_membership` guard
  is in the fast ownership tier and Linux Docker safety runner. The guard
  failed first because the owner did not exist, then passed locally and in Linux
  Docker; focused handshake, decrypt-failure, and peer-index tracking tests
  passed; the full default fast ownership tier passed. No perf smoke was run
  because this is an ownership/dispatch boundary slice, not a route-choice,
  timeout, queue capacity, send backpressure threshold, throughput, or Mac
  sender behavior change.
- FIPS `6f44c93` makes the decrypt-worker registration mirror explicit.
  `DecryptSessionRegistrations` owns the rx-loop mirror of sessions accepted by
  decrypt-worker shards. Rx-loop dispatch now asks that owner whether a session
  is worker-owned, registration only marks a session after `register_session`
  succeeds, and deregistration only asks the worker to evict sessions that were
  locally registered. The new
  `decrypt_session_registrations_own_worker_acceptance_and_unregister_gate`
  guard is in the fast ownership tier and Linux Docker safety runner. The guard
  failed first because the owner did not exist, then passed locally and in Linux
  Docker; focused promotion, handshake, decrypt-failure, and session-index
  tests passed; the full default fast ownership tier passed. No perf smoke was
  run because this is an ownership/dispatch boundary slice, not a route-choice,
  timeout, queue capacity, send backpressure threshold, throughput, or Mac
  sender behavior change.
- FIPS `103cc36` makes the identity cache explicit.
  `IdentityCache` owns FipsAddress/NodeAddr prefix derivation, public-key
  validation, rejected-claim preservation, lookup LRU touch, LRU eviction, and
  npub/pubkey views for discovery proof verification and endpoint delivery.
  Node cache helpers keep the same behavior, but no longer inspect or mutate a
  raw prefix map directly. The new
  `identity_cache_owns_prefix_validation_lru_touch_and_lookup_views` guard is
  in the fast ownership tier and Linux Docker safety runner. The guard failed
  first because the owner did not exist, then passed locally and in Linux
  Docker; focused identity-cache and discovery tests passed; the full default
  fast ownership tier passed. No perf smoke was run because this is an
  ownership/type-boundary slice, not a route-choice, timeout, queue capacity,
  send backpressure threshold, throughput, or Mac sender behavior change.
- `2026-06-09` audit at nvpn `f8381429` plus FIPS `f17ab93` re-ran the
  source-safe harness self-tests, nvpn TUN-to-mesh full-queue guard, FIPS fast
  ownership tier, and full FIPS Linux deterministic runner. A short current-head
  local-FIPS Docker perf smoke also passed all four phases. Clean-underlay ran
  at roughly `2166/2192 Mbps`, constrained-underlay at `130/128 Mbps`,
  worker-queue-pressure at `127/128 Mbps`, and rx-maintenance-fault at
  `2229/2253 Mbps`; all load/post-load tunnel-ping loss was `0%`, direct UDP
  byte counters advanced in every phase, and worker pressure exposed expected
  decrypt queue-full/bulk-drop counters without a wedge. Raw audit artifacts
  were written to `/tmp/nvpn-fips-current-smoke-20260609T031737`; the
  `phase-summary.tsv` SHA-256 is
  `ca6e43ba389d158707666dddc39e2416b9a00cdc59f15ba2b70cd92907623487`.
  This is current Linux/Docker safety evidence for continuing guarded
  architecture slices; it is not a one-shot rewrite claim, not a clean host/VM
  throughput baseline, and not real Mac-to-Mac validation.
- FIPS `739c3cd` makes configured peer send weights explicit.
  `ConfiguredPeerSendWeights` owns configured-peer identity parsing, invalid
  identity skipping, the explicit configured-peer scheduling weight, and the
  default fallback weight used for unconfigured peers. Node construction,
  identity-preserving construction, and live peer reload all rebuild the same
  owner; the hot send path delegates the final lookup. The new
  `configured_peer_send_weights_own_identity_parse_and_default_policy` guard is
  in the fast ownership tier and Linux Docker safety runner. The guard failed
  first because the owner did not exist, then passed locally and in Linux
  Docker; `bash -n`, `cargo fmt --check`, `cargo check -p fips-core --release`,
  `git diff --check`, leak scan, and the full default fast ownership tier
  passed. No perf smoke was run because this is an ownership/type-boundary
  slice, not a route-choice, timeout, queue capacity, send-weight threshold,
  throughput, or Mac sender behavior change.
- FIPS `5b4249a` makes the link-address reverse lookup explicit and speeds up
  the fast ownership tier. `LinkAddressIndex` owns `(transport_id,
  remote_addr) -> link_id` insertion, replacement, lookup, and stale-safe
  removal. `Node::remove_link` now removes an address entry only when it still
  points to the link being removed, preserving cross-connection winner entries
  against stale loser cleanup. The new
  `link_address_index_owns_lookup_replace_and_stale_safe_remove` guard is in
  the fast ownership tier and Linux Docker safety runner. The same commit
  batches the default `scripts/test-dataplane-ownership-fast.sh` run through
  `_own` plus the non-matching no-wedge groups, while `--no-batch-defaults`
  preserves exact per-filter replay. Verification passed: the guard failed
  first because the owner did not exist, then passed locally and in Linux
  Docker; focused handshake coverage passed; `bash -n`, `cargo fmt --check`,
  `cargo check -p fips-core --release`, `git diff --check`, leak scan, and the
  accelerated full default fast ownership tier passed in about 22 seconds on
  warm artifacts. No perf smoke was run because this is an ownership/dispatch
  boundary and workflow-speed slice, not a route-choice, timeout, queue
  capacity, send-weight threshold, throughput, or Mac sender behavior change.
- FIPS `aa020d0` makes link storage and reverse address dispatch a single
  owner. `LinkRegistry` owns the active `Link` map plus address index; insert,
  replace, and remove keep both sides consistent and stale-safe. The new
  `link_registry_owns_storage_address_index_and_stale_safe_cleanup` guard is in
  the fast ownership tier and Linux Docker safety runner. Verification passed:
  the guard failed first because the owner did not exist, then passed locally;
  focused handshake, spanning-tree, and ownership coverage passed; script
  syntax checks, formatting, release check, leak scan, and the full accelerated
  fast ownership tier with Linux Docker passed. No perf smoke was run because
  this is route/dispatch ownership groundwork, not a route-choice, timeout,
  queue capacity, send-weight threshold, throughput, or Mac sender change.
- FIPS `4481951` makes active peer storage and receiver-index dispatch a single
  owner. `ActivePeerRegistry` owns the `NodeAddr -> ActivePeer` map plus active
  `(transport_id, our_index) -> NodeAddr` dispatch, preserving the current peer
  map API while removing the separate `Node::peers_by_index` field. The new
  `active_peer_registry_owns_storage_session_index_and_stale_safe_cleanup`
  guard is in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the owner did not exist,
  then passed locally; focused handshake, rekey, decrypt-failure, and ownership
  coverage passed; formatting, release check, diff check, leak scan, and the
  full fast ownership tier with Linux Docker passed. No perf smoke was run
  because this is peer/session dispatch ownership groundwork, not a
  route-choice, timeout, queue capacity, throughput, or Mac sender change.
- FIPS `5198191` makes pending handshake connection storage and active peer
  storage a single lifecycle owner. `PeerLifecycleRegistry` owns the `LinkId ->
  PeerConnection` map plus `ActivePeerRegistry`; `Node::connections` is gone,
  and pending connection call sites now go through lifecycle methods. The new
  `peer_lifecycle_registry_owns_connection_and_active_peer_storage` guard is in
  the fast ownership tier and Linux Docker safety runner. Verification passed:
  the guard failed first because the owner did not exist, then passed locally;
  focused connection-management, handshake, timeout, cross-connection, and
  ownership coverage passed; formatting, warning-clean release check, diff
  check, leak scan, and the full fast ownership tier with Linux Docker passed.
  No perf smoke was run because this is lifecycle ownership groundwork, not a
  route-choice, timeout, queue capacity, throughput, or Mac sender change.
- FIPS `ab74260` gives end-to-end FSP session storage a single owner.
  `SessionRegistry` wraps the `NodeAddr -> SessionEntry` table while preserving
  the current map-like call-site API. The new
  `session_registry_owns_endpoint_session_storage_replace_and_cleanup` guard is
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the owner did not exist, then passed
  locally; focused `session`, `handshake`, and ownership coverage passed;
  formatting, warning-clean release check, diff check, private-string scan, and
  the full `./scripts/test-dataplane-ownership-fast.sh` tier passed, including
  Linux Docker. No perf smoke was run because this is endpoint session
  ownership groundwork toward `PeerRuntime`, not a route-choice, timeout, queue
  capacity, throughput, or Mac sender behavior change.
- FIPS `aaad4ef` folds the decrypt-worker registration mirror into
  `SessionRegistry`. The session owner now owns the `NodeAddr -> SessionEntry`
  table plus the rx-loop mirror of worker-accepted decrypt sessions, and
  `Node::decrypt_registered_sessions` is gone. The new
  `session_registry_owns_endpoint_session_storage_and_worker_registration_mirror`
  guard is in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because `SessionRegistry` lacked
  worker-registration APIs, then passed locally; focused worker-registration,
  `test_promote_registers_decrypt_worker`, `handshake`, `rekey`, `unit`, and
  ownership coverage passed; formatting, warning-clean release check, diff
  check, private-string scan, the full fast ownership tier with Linux Docker,
  and a targeted Linux Docker connected-UDP deregistration guard passed. No
  perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `0416b80` makes session-index removal state a peer-lifecycle owner
  decision. `PeerLifecycleRegistry` now removes an active receiver-index entry
  and returns the removed owner plus whether that owner still has another index;
  `Node::deregister_session_index` uses that single result for connected-UDP
  cleanup instead of doing a separate membership query after removal. The new
  `peer_lifecycle_registry_owns_session_index_removal_and_remaining_owner_state`
  guard is in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the atomic removal API
  did not exist, then passed locally; focused session-index, active-peer, and
  lifecycle guards passed; `unit`, `handshake`, and `rekey` filters passed;
  formatting, warning-clean release check, diff check, private-string scan, the
  full fast ownership tier with Linux Docker, and a targeted Linux Docker
  connected-UDP deregistration guard passed. No perf smoke was run because this
  is ownership-boundary work, not a route, queue-cap, sender, or throughput
  change.
- FIPS `d4b30ec` makes active-peer teardown indices a peer-lifecycle owner
  decision. `PeerLifecycleRegistry::remove_with_session_indices` now removes
  the active peer and returns a typed teardown plan for current, rekey, pending,
  and previous receiver-index keys; `Node::remove_active_peer` consumes that
  plan instead of reading every `ActivePeer` index slot. The new
  `peer_lifecycle_registry_owns_active_peer_teardown_session_indices` guard is
  in the fast ownership tier and Linux Docker safety runner. Verification
  passed: the guard failed first because the teardown API and index-kind types
  did not exist, then passed locally; focused teardown, disconnect, and
  decrypt-failure coverage passed; `unit` passed; formatting, warning-clean
  release check, diff check, private-string scan, and the full fast ownership
  tier with Linux Docker passed. No perf smoke was run because this is
  ownership-boundary work, not a route, queue-cap, sender, or throughput change.
- FIPS `2507693` makes active-peer insertion plus current receiver-index
  registration a peer-lifecycle owner decision.
  `PeerLifecycleRegistry::insert_with_current_session_index` now installs active
  peer storage and registers the current `(transport_id, our_index)` dispatch
  key as one operation, returning the replaced active peer and replaced
  session-index owner for observability; initial promotion and
  cross-connection-winner promotion consume it instead of separately inserting
  active peer storage and receiver-index dispatch. New guard:
  `peer_lifecycle_registry_owns_active_peer_insert_and_current_session_index`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API/result
  type did not exist, then passed locally; focused peer-lifecycle ownership
  coverage, `handshake`, and `unit` passed; `cargo fmt --check`, warning-clean
  `cargo check -p fips-core --release`, `git diff --check`, private-string
  scan, and the full `./scripts/test-dataplane-ownership-fast.sh` tier with
  Linux Docker passed. No perf smoke was run because this is ownership-boundary
  work, not a route, queue-cap, sender, or throughput change.
- FIPS `582a50f` makes active-peer current session/path replacement a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::replace_current_session_and_path` now replaces the
  active peer Noise session, current indices, link id, transport/address,
  optional remote epoch, and connected timestamp as one operation. It registers
  the new current receiver index before returning the old current index to
  `Node` for decrypt-worker/connected-UDP teardown; the msg2 outbound
  alternate-path refresh and outbound cross-connection-winner paths consume
  that operation instead of separately mutating the peer, deregistering the old
  index, and inserting the new current index. New guard:
  `peer_lifecycle_registry_owns_current_session_replacement_and_index_handoff`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `handshake`,
  and `unit` passed; `cargo fmt --check`, warning-clean `cargo check -p
  fips-core --release`, `git diff --check`, private-string scan, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `049aaa7` makes pending FMP rekey session installation a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::install_pending_rekey_session_and_index` now stores
  the pending Noise session, pending local/remote indices, optional remote
  epoch, peer-initiated rekey dampening, and pending receiver-index dispatch as
  one operation. The rekey msg1 responder path and rekey msg2 initiator path
  consume that operation instead of separately mutating `ActivePeer`
  pending-session state and inserting the pending receiver index. New guard:
  `peer_lifecycle_registry_owns_pending_rekey_session_and_index_registration`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `rekey`,
  `handshake`, and `unit` passed; `cargo fmt --check`, warning-clean
  `cargo check -p fips-core --release`, `git diff --check`, private-string
  scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `5196ed8` makes authenticated FMP receive bookkeeping a peer-lifecycle
  owner decision.
  `PeerLifecycleRegistry::record_authenticated_fmp_receive` now owns decrypt
  failure reset, authenticated path rotation, link receive stats, peer
  liveness touch, MMP receiver counters, spin-bit observation, and the
  connected-UDP clear signal returned to `Node`. The encrypted-frame handler
  consumes that operation after worker-owned decrypt returns authenticated
  plaintext instead of separately mutating the active peer. New guard:
  `peer_lifecycle_registry_owns_authenticated_fmp_receive_bookkeeping`,
  included in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `encrypted`,
  `rekey`, and `unit` passed; `cargo fmt --check`, warning-clean
  `cargo check -p fips-core --release`, `git diff --check`, private-string
  scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `6ce47d9` makes link-dead direct-path degradation a peer-lifecycle
  owner decision.
  `PeerLifecycleRegistry::mark_link_dead_direct_path` now owns active-peer
  stale marking, degraded-link reporting, and connected-UDP socket/drain
  teardown while preserving the peer for direct probes. `Node` still owns the
  separate session-direct-degradation hold and queued-packet preservation
  policy. New guard:
  `peer_lifecycle_registry_owns_link_dead_direct_path_degradation`, included
  in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `link_dead`,
  `disconnect`, and `unit` passed; `cargo fmt --check`, warning-clean
  `cargo check -p fips-core --release`, `git diff --check`, private-string
  scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `96a2f5f` makes current receiver-index registration repair a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::ensure_current_session_index_registered` now owns
  missing/stale current `(transport_id, our_index)` dispatch repair for an
  active peer and returns `MissingActivePeer`, `MissingTransportId`,
  `MissingLocalIndex`, `AlreadyRegistered`, or `Repaired`. `Node` consumes the
  typed result for logging only, so the repair decision no longer open-codes
  active-peer and session-index registry state at the call site. New guard:
  `peer_lifecycle_registry_owns_current_session_index_repair`, included in the
  fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API and
  result type did not exist, then passed locally; focused peer-lifecycle
  ownership, `rekey`, `handshake`, `encrypted`, and `unit` passed; `cargo fmt
  --check`, warning-clean `cargo check -p fips-core --release`, `git diff
  --check`, private-string scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `ea3c79d` makes FMP send bookkeeping a peer-lifecycle owner decision.
  `PeerLifecycleRegistry::record_fmp_send_bookkeeping` now owns active-peer
  link send stats plus MMP sender counters for FMP wire sends. The normal
  worker-send path, inline fallback send path, and pipelined session/datagram
  send path consume that owner instead of open-coding `ActivePeer` stats and
  MMP sender mutation at each call site. New guard:
  `peer_lifecycle_registry_owns_fmp_send_bookkeeping`, included in the fast
  ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API and
  result type did not exist, then passed locally; focused peer-lifecycle
  ownership, `fmp_worker`, `pipelined`, `selected_send`,
  `reserve_fsp_worker_send`, `unit`, and broad `session` filters passed;
  `cargo fmt --check`, warning-clean `cargo check -p fips-core --release`,
  `git diff --check`, private-string scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work, not a route,
  queue-cap, sender, or throughput change.
- FIPS `5bf1714` makes FSP send bookkeeping a session-registry owner decision.
  `SessionRegistry::record_fsp_send_bookkeeping` now owns FSP data counters,
  MMP sender counters, idle-touch policy, and optional outbound next-hop
  recording for session data, endpoint data, pipelined session/datagram,
  session-control, and standalone CoordsWarmup sends. New guard:
  `session_registry_owns_fsp_send_bookkeeping`, included in the fast ownership
  tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the registry API and
  result type did not exist, then passed locally; focused session-registry
  ownership, `pipelined`, broad `session`, formatting, warning-clean release
  check, diff check, private-string scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work. The plan is to
  measure continuously but cheaply: exact short smokes after hot-path or
  behavior-touching slices, after batches of pure ownership slices, before
  larger peer/session runtime rewrites, and before/after sender, queue,
  batching, route, connected-UDP, or maintenance-timing behavior changes.
- A post-ownership-batch short local-FIPS Docker perf checkpoint at nvpn
  `428c821f` plus FIPS `5bf1714` passed all four phases. Clean-underlay ran at
  roughly `2147/2275 Mbps`; constrained-underlay at `136.9/136.6 Mbps`;
  worker-queue-pressure at `122.0/120.9 Mbps` with load at
  `126.6/129.1 Mbps`; rx-maintenance-fault at `2242.8/2222.9 Mbps` with load
  at `2294.9/2235.0 Mbps`. Load/post ping loss stayed `0%`, direct UDP
  counters advanced in every phase, expected queue-full/drop counters appeared
  under worker pressure, and the failure summary contained only the header.
- FIPS `1241961` makes connected-UDP activation planning a peer-lifecycle owner
  decision. `PeerLifecycleRegistry::connected_udp_activation_plan` now owns the
  active-peer scan for healthy established UDP peers, the already-installed
  connected-UDP count, and stable configured-peer-before-discovered activation
  order. The connected-UDP handler still owns async transport resolution,
  socket open, and drain spawn, but it consumes the lifecycle owner-produced
  plan instead of walking active peer storage and reparsing configured peers per
  candidate. New guard:
  `peer_lifecycle_registry_owns_connected_udp_activation_plan`, included in the
  fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API did not
  exist, then passed locally; focused peer-lifecycle ownership, `connected_udp`,
  broad `unit`, formatting, warning-clean release check, diff check,
  private-string scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  No perf smoke was run because this is ownership-boundary work; the current
  perf checkpoint remains the nvpn `428c821f` plus FIPS `5bf1714` short Docker
  smoke above.
- FIPS `e80a482` makes connected-UDP socket/drain install and clear a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::install_connected_udp_if_eligible` owns the final
  activation-race eligibility recheck and `ActivePeer` socket/drain mutation,
  while `PeerLifecycleRegistry::clear_connected_udp_for_peer` owns idempotent
  clear results. The connected-UDP handler still owns async transport
  resolution, socket open, drain spawn, budget checks, and perf/log emission,
  but consumes typed lifecycle results instead of mutating peer connected-UDP
  state directly. New guard:
  `peer_lifecycle_registry_owns_connected_udp_install_and_clear`, included in
  the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API/result
  types did not exist, then passed locally; focused `connected_udp` and
  peer-lifecycle ownership filters passed; broad `unit` passed with `169`
  tests; formatting, warning-clean release check, diff check, private-string
  scan, bash syntax check, and the full
  `./scripts/test-dataplane-ownership-fast.sh` tier with Linux Docker passed.
  A follow-up short local-FIPS Docker perf checkpoint at nvpn `9fa7ae91` plus
  FIPS `e80a482` passed all four phases: clean-underlay roughly
  `2192/2119 Mbps`, constrained-underlay `134.7/135.0 Mbps`,
  worker-pressure baseline `146.5/152.2 Mbps` with load `150.2/140.2 Mbps`,
  and rx-maintenance baseline `2216.1/2176.7 Mbps` with load
  `2255.5/2212.2 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct UDP
  counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. This is Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `750ebb4` makes FMP send preparation and inline/worker seal reservation
  a peer-lifecycle owner decision. `PeerLifecycleRegistry::prepare_fmp_send`
  snapshots transport ID, current transport address, receiver index, flags,
  payload length, timestamp, and optional connected UDP socket without
  consuming a Noise send counter. Worker counter/header/cipher reservation and
  inline counter/header/seal reservation now happen through lifecycle owner
  methods, while `Node::send_encrypted_link_message_with_ce` still owns
  transport readiness, worker target resolution, dispatch, actual send, and
  send bookkeeping. New guard:
  `peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths`, included
  in the fast ownership tier and Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle APIs did
  not exist, then passed locally; focused `fmp_worker`, the default local
  ownership tier, warning-clean release check, bash syntax check, diff check,
  private-string scan, and a focused Linux Docker slice for the new/adjacent
  FMP guards passed.
  Because this slice touches send hot-path preparation, an exact short
  local-FIPS Docker perf checkpoint at nvpn `df8ad39d` plus FIPS `750ebb4`
  passed all four phases: clean-underlay roughly `2261/2278 Mbps`,
  constrained-underlay `131.2/132.7 Mbps`, worker-pressure baseline
  `129.3/133.0 Mbps` with load `128.7/129.2 Mbps`, and rx-maintenance baseline
  `2260.6/2296.3 Mbps` with load `2272.4/2149.1 Mbps`. Load/post tunnel-ping
  loss stayed `0%`, direct UDP counters advanced in every phase, worker
  pressure exposed expected queue-full/drop counters, and `failure-summary.tsv`
  contained only the header. Phase summary hash:
  `f0bde446cf106d7a265a01bc213f87a818f0f1bfe2359dba858884f024418d16`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  A heavier connected-UDP-on platform row also passed with phase summary hash
  `08d22f71655bfcc7760b81488518390125cf7eec1f9f46baaebe938b9a417f79`, failure
  summary hash `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`,
  and log hash `0d654886bdd8bb492fea1569e4d82183cd27a618d9284884e8b4a71c136d3564`.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `9c14552` makes FMP worker packet preparation a peer-lifecycle owner
  decision. `PeerLifecycleRegistry::prepare_fmp_worker_send` owns the
  worker-side payload-length check, counter/header/cipher reservation, FMP wire
  buffer layout, timestamp/plaintext placement, and predicted byte count for
  worker sends. `Node::send_encrypted_link_message_with_ce` still owns
  transport readiness, worker-target resolution, dispatch, actual send, and
  send bookkeeping. The existing guard
  `peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths` was
  extended to pin this boundary and is included in the fast ownership tier and
  Linux Docker safety runner.
  Verification passed: the guard failed first because the lifecycle API and
  payload-mismatch error did not exist, then passed locally; adjacent
  `fmp_worker`, the default local ownership tier, warning-clean release check,
  bash syntax check, diff check, private-string scan, broad local `unit`, and a
  focused Linux Docker FMP slice passed.
  Because this slice touches send hot-path packet preparation, an exact short
  local-FIPS Docker perf checkpoint at nvpn `df8ad39d` plus FIPS `9c14552`
  passed all four phases: clean-underlay roughly `2354/2283 Mbps`,
  constrained-underlay `130.2/132.6 Mbps`, worker-pressure baseline
  `126.3/127.7 Mbps` with load `132.3/129.8 Mbps`, and rx-maintenance baseline
  `2316.5/2270.6 Mbps` with load `2271.9/2281.4 Mbps`. Load/post tunnel-ping
  loss stayed `0%`, direct UDP counters advanced in every phase, worker
  pressure exposed expected queue-full/drop counters, and `failure-summary.tsv`
  contained only the header. Phase summary hash:
  `ccff9d128ce1d2077407181a07b0e63c1a83e21ab06346ee08460225a97aa926`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `cb59aab` makes pipelined endpoint/FSP FMP worker reservation a
  peer-lifecycle owner decision.
  `PeerLifecycleRegistry::reserve_prepared_fmp_worker_send` owns the FMP worker
  counter, header, cipher reservation, and predicted outer wire bytes for both
  plain FMP worker sends and pipelined endpoint-data sends.
  `PeerLifecycleRegistry::fmp_worker_send_available` preserves the previous
  counter-safety invariant by checking worker-cipher availability before the
  endpoint path reserves an FSP counter.
  `try_send_session_endpoint_data_pipelined` still owns route lookup, MTU/FSP
  reservation, wire layout around reserved headers, worker-target dispatch, and
  send policy. The guard
  `peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths` failed
  first because the pipelined reservation API did not exist, then passed.
  Verification passed: focused guard, focused pipelined wire guard, adjacent
  `fmp_worker` and `pipelined` filters, default local ownership fast tier,
  focused Linux Docker ownership slice, broad local `unit`, warning-clean
  release check, `cargo fmt --check`, bash syntax check, diff check, and
  private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, an exact short
  local-FIPS Docker perf checkpoint at nvpn `df8ad39d` plus FIPS `cb59aab`
  passed all four phases: clean-underlay baseline roughly
  `2244.8/2086.7 Mbps` with load `2138.2/2245.7 Mbps`,
  constrained-underlay baseline `136.6/134.9 Mbps` with load
  `135.6/134.6 Mbps`, worker-pressure baseline `123.0/151.4 Mbps` with load
  `112.0/133.9 Mbps`, and rx-maintenance baseline `2072.8/2089.8 Mbps` with
  load `1347.0/2191.3 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. Phase summary hash:
  `876e0693da982761985e22c3d0ef12faa56657c599d6facedb3a7b1a40a609aa`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `49c9db1` makes endpoint-data FSP worker reservation a session-registry
  owner decision. `SessionRegistry::reserve_endpoint_data_fsp_worker_send` owns
  source path-MTU seeding, established-session validation, and FSP
  counter/header/cipher reservation for pipelined endpoint-data sends.
  `try_send_session_endpoint_data_pipelined` still owns route lookup, FMP
  preparation/reservation, wire construction around reserved headers,
  worker-target dispatch, and send policy. The guard
  `session_registry_owns_endpoint_fsp_worker_reservation_and_path_mtu_seed`
  failed first because the input/error types and registry API did not exist,
  then passed. Verification passed: focused guard, `session_registry_owns`,
  `pipelined`, `fsp_worker`, prior peer-lifecycle FMP guard, default local
  ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), warning-clean release check, `cargo fmt --check`, bash
  syntax check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, an exact short
  local-FIPS Docker perf checkpoint at nvpn `df8ad39d` plus FIPS `49c9db1`
  passed all four phases: clean-underlay baseline roughly
  `2318.1/2098.1 Mbps` with load `2279.4/2215.4 Mbps`,
  constrained-underlay baseline `138.1/137.1 Mbps` with load
  `135.7/135.2 Mbps`, worker-pressure baseline `123.8/121.8 Mbps` with load
  `119.9/124.8 Mbps`, and rx-maintenance baseline `2310.5/2191.0 Mbps` with
  load `2178.7/2283.9 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. Phase summary hash:
  `29cb58491d63b06a1afd7c3ae880265fc3639d59da4b03bf8b553d5d8ef4c6aa`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
- FIPS `3a746bb` makes pipelined endpoint wire payload sizing and nested worker
  seal offsets an owned wire-plan boundary. `PipelinedEndpointWirePlan` owns
  link plaintext length and FMP payload length calculation, while
  `PipelinedEndpointWire::into_worker_wire` owns the FMP/FSP
  reservation-to-worker-wire handoff and `FspSealJob` offsets.
  `try_send_session_endpoint_data_pipelined` still owns route lookup,
  transport target resolution, peer/session reservation ordering, FMP/FSP
  bookkeeping, backpressure/drop policy, and worker dispatch. The guard
  `pipelined_endpoint_wire_plan_owns_payload_sizing_and_worker_offsets` failed
  first because the plan/worker-wire owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, and `fsp_worker` filters, default local ownership
  fast tier, focused Linux Docker ownership slice, broad local `unit` (`171`
  tests), warning-clean release check, `cargo fmt --check`, bash syntax check,
  diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, an exact short
  local-FIPS Docker perf checkpoint at nvpn `df8ad39d` plus FIPS `3a746bb`
  passed all four phases: clean-underlay baseline roughly
  `2289.3/2226.0 Mbps` with load `2155.9/2221.0 Mbps`,
  constrained-underlay baseline `138.5/137.6 Mbps` with load
  `136.2/135.2 Mbps`, worker-pressure baseline `124.3/131.8 Mbps` with load
  `131.5/120.4 Mbps`, and rx-maintenance baseline `2198.9/2265.3 Mbps` with
  load `2215.3/2205.4 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. Phase summary hash:
  `aba2e194c4eae6eec3d7f3c53ad1de4a1481f664e2fba234d976b9e260f765e1`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
- FIPS `2fb3fbd` makes pipelined endpoint dispatch policy an owned plan.
  `PipelinedEndpointDispatchPlan` owns endpoint FSP payload length, FSP worker
  reservation input, FSP send bookkeeping input, bulk/control worker lane
  policy, direct-path degradation drop suppression, drop-on-backpressure, and
  scheduling weight handoff. `try_send_session_endpoint_data_pipelined` still
  owns route lookup, transport target resolution, peer/session reservation
  ordering, FMP bookkeeping, and worker dispatch. The guard
  `pipelined_endpoint_dispatch_plan_owns_worker_policy_and_bookkeeping` failed
  first because the dispatch plan owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, and `fsp_worker` filters, default local ownership
  fast tier, focused Linux Docker ownership slice, broad local `unit` (`171`
  tests), warning-clean release check, `cargo fmt --check`, bash syntax check,
  diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, an exact short
  local-FIPS Docker perf checkpoint at nvpn `df8ad39d` plus FIPS `2fb3fbd`
  passed all four phases: clean-underlay baseline roughly
  `2238.9/2126.0 Mbps` with load `2160.6/2189.9 Mbps`,
  constrained-underlay baseline `137.9/137.3 Mbps` with load
  `136.9/136.1 Mbps`, worker-pressure baseline `130.3/122.5 Mbps` with load
  `125.0/123.1 Mbps`, and rx-maintenance baseline `2072.3/2031.9 Mbps` with
  load `2092.3/2172.6 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. Phase summary hash:
  `b677a5ecea6390c224e95d30c6d190850269494104d8bdd4c32d2f47ef9e37e4`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `34bc3f2` makes the pipelined endpoint send-plan handoff an owned
  boundary. `PipelinedEndpointSendPlan` now groups the wire plan, dispatch
  policy, selected send target handoff, FMP/FSP reservations, worker-job
  construction, FMP bookkeeping facts, FSP bookkeeping input, and originated
  byte accounting into one prepared send. `try_send_session_endpoint_data_pipelined`
  still sequences route lookup, path-MTU discovery, transport lookup, registry
  reservation calls, bookkeeping application, and worker dispatch, but no
  longer assembles the wire, send policy, worker job, and bookkeeping facts in
  one open-coded block. The guard
  `pipelined_endpoint_send_plan_owns_worker_job_and_bookkeeping_handoff`
  failed first because the send-plan owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), warning-clean release check, `cargo fmt --check`, bash
  syntax check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, an exact short
  local-FIPS Docker perf checkpoint at nvpn `e41828f2` plus FIPS `34bc3f2`
  passed all four phases: clean-underlay baseline roughly
  `2289.4/2187.3 Mbps` with load `2185.5/2231.1 Mbps`,
  constrained-underlay baseline `137.1/136.9 Mbps` with load
  `138.2/133.8 Mbps`, worker-pressure baseline `123.4/121.9 Mbps` with load
  `121.8/125.5 Mbps`, and rx-maintenance baseline `2165.2/2242.8 Mbps` with
  load `2138.9/2216.4 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. Phase summary hash:
  `8794347cac2b71309a1b13b52948423d2f7f45210f69b03b5fc8f6204b9e85a0`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This remains a previous all-green exact short checkpoint and is Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `58f36c0` makes the pipelined endpoint runtime send plan an owned
  boundary. `PipelinedEndpointRoutePlan` now owns selected route facts, source
  address, next-hop address, path MTU, default TTL, scheduling weight, and
  direct-path block state. `PipelinedEndpointRuntimeSendPlan` combines that
  route plan with `PipelinedEndpointSendPlan` and `FmpSendPreparation`, checks
  that the prepared FMP payload matches the send plan, and hands the final
  bookkeeping/dispatch commit to `PipelinedEndpointPreparedSend::commit`.
  `try_send_session_endpoint_data_pipelined` now coordinates transport lookup,
  worker availability, reservation calls, and dispatch around the runtime send
  plan instead of open-coding route and FMP preparation itself. The guard
  `pipelined_endpoint_runtime_send_plan_owns_route_and_fmp_preparation` failed
  first because the route/runtime send-plan owners did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), warning-clean release check, `cargo fmt`, bash syntax
  check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short local-FIPS Docker perf attempt at nvpn `0b79cfba` plus FIPS
  `58f36c0`. Clean-underlay passed: baseline roughly
  `2176.4/2265.0 Mbps`, load `2233.1/2017.8 Mbps`, load/post tunnel-ping loss
  `0%`, and direct UDP counters advanced both ways. Constrained-underlay then
  failed because reverse TCP reached `94.4 Mbps` against the `100 Mbps` floor;
  forward TCP was `127.3 Mbps`, direct UDP counters advanced both ways, and the
  remaining phases were not reached. Phase summary hash:
  `f709bc24cced4ddfa6c10033c198a541f492d4d8d5b6392617abc24e588736f7`;
  failure summary hash:
  `2ac82a41cfe0a73734ac99e7db2db6cf718cc08113af00ddee15fe096459a85e`.
  This is a watchlist signal for the next sender/runtime boundary, not a green
  checkpoint, and remains Linux/Docker evidence, not real Mac-to-Mac
  validation.
- FIPS `a8ece85` makes the pipelined endpoint runtime dispatch an owned
  boundary. `PipelinedEndpointRuntimeSendDispatch` owns the runtime send plan,
  resolved send target, prepared FMP worker reservation, and FSP worker
  reservation through prepared-send construction and commit. The hot-path
  coordinator now clones the worker pool, prepares the runtime send plan,
  prepares the runtime dispatch, and commits it; transport lookup, send-target
  resolution, worker availability, reservation calls, prepared-send
  construction, and dispatch handoff are grouped under one runtime operation.
  The guard
  `pipelined_endpoint_runtime_dispatch_owns_target_reservations_and_prepared_send`
  failed first because the dispatch owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), warning-clean release check, `cargo fmt`, bash syntax
  check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short local-FIPS Docker perf checkpoint at nvpn `e8f883cc` plus FIPS
  `a8ece85`. It passed all four phases: clean-underlay baseline roughly
  `2251.1/2263.6 Mbps` with load `2220.6/2139.9 Mbps`,
  constrained-underlay baseline `137.4/135.7 Mbps` with load
  `137.0/136.6 Mbps`, worker-pressure baseline `133.9/118.8 Mbps` with load
  `124.7/126.4 Mbps`, and rx-maintenance baseline `2151.2/1991.3 Mbps` with
  load `2105.2/2234.0 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. Phase summary hash:
  `627f3babc838330def60fce4fc90ed0dfb882e49aa3fb5552b8947f9b4e840b8`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `f1689c7` introduces the first peer-runtime send snapshot boundary.
  `PeerRuntimeSendSnapshot` owns the peer address, prepared FMP send metadata,
  and FMP worker-send availability from a single active-peer read. The
  pipelined runtime dispatch now consumes the snapshot for worker availability
  and FMP reservation instead of rereading active peer state after route/FMP
  preparation. The guard
  `peer_runtime_send_snapshot_owns_fmp_metadata_and_worker_availability`
  failed first because the snapshot/reservation API did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `peer_lifecycle_registry_owns`, `session_registry_owns`, `fmp_worker`, and
  `connected_udp` filters, default local ownership fast tier, focused Linux
  Docker ownership slice, broad local `unit` (`172` tests), warning-clean
  release check, `cargo fmt`, bash syntax check, diff check, and private-string
  scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short local-FIPS Docker perf checkpoint at nvpn `e8f883cc` plus FIPS
  `f1689c7`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/f1689c7-short-smoke-20260609Tpeer-runtime-snapshot \
PROJECT_NAME=nostr-vpn-e2e-fips-f1689c7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2220.8/2144.8 Mbps` with load `2133.7/2091.4 Mbps`,
  constrained-underlay baseline `137.5/137.8 Mbps` with load
  `136.6/135.9 Mbps`, worker-pressure baseline `122.9/136.3 Mbps` with load
  `154.9/154.7 Mbps`, and rx-maintenance baseline `2189.3/2029.4 Mbps` with
  load `2247.4/2202.8 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `8c91b6bf54d9ea607155a29db29de8828490dffa33829f6601090ad3031303f6`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `f4eefe6` grows the first peer-runtime send snapshot into a route
  snapshot. `PeerRuntimeRouteSnapshot` owns the next-hop peer address,
  transport/current-address path-MTU seed, prepared-FMP inputs, and FMP
  worker-send availability from a single active-peer read. The pipelined
  runtime send path now derives both route planning and the FMP send snapshot
  from that captured view instead of reading active peer state once for path
  MTU and again for FMP/worker metadata. The guard
  `peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs` failed
  first because the route-snapshot API did not exist, then passed.
  Verification passed: focused guard, the previous send-snapshot guard,
  adjacent `pipelined`, `peer_lifecycle_registry_owns`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`173` tests), warning-clean release check, `cargo fmt`, bash syntax
  check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short local-FIPS Docker perf checkpoint at nvpn `e8f883cc` plus FIPS
  `f4eefe6`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/f4eefe6-short-smoke-20260609Tpeer-runtime-route-snapshot \
PROJECT_NAME=nostr-vpn-e2e-fips-f4eefe6-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2256.1/2146.5 Mbps` with load `2210.0/2129.1 Mbps`,
  constrained-underlay baseline `129.3/128.6 Mbps` with load
  `128.2/129.5 Mbps`, worker-pressure baseline `131.7/144.1 Mbps` with load
  `154.0/145.4 Mbps`, and rx-maintenance baseline `2242.8/2199.6 Mbps` with
  load `2204.6/2129.4 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `6eda85cfa108c991d6e84cec088a9e94bb3d1cf18a273f1f7595dcb62e4ae072`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `0fd7817` makes the peer-route-snapshot handoff explicit inside the
  pipelined endpoint runtime send plan.
  `PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot` now owns the
  conversion from route plan plus send plan plus `PeerRuntimeRouteSnapshot`
  into the runtime send plan, derives the FMP send snapshot internally, and
  rejects a route next-hop that does not match the captured peer snapshot
  address. The guard
  `pipelined_endpoint_runtime_send_plan_owns_peer_route_snapshot_handoff`
  failed first because the constructor and mismatch error did not exist, then
  passed. Verification passed: focused guard, adjacent `pipelined`,
  previous route-snapshot, `peer_lifecycle_registry_owns`, and
  `session_registry_owns` filters, default local ownership fast tier, focused
  Linux Docker ownership slice, broad local `unit` (`173` tests), warning-clean
  release check, `cargo fmt`, bash syntax check, diff check, and private-string
  scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short local-FIPS Docker perf checkpoint at nvpn `6806bf50` plus FIPS
  `0fd7817`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/0fd7817-short-smoke-20260609Truntime-route-handoff \
PROJECT_NAME=nostr-vpn-e2e-fips-0fd7817-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2210.5/2226.2 Mbps` with load `2168.9/2120.4 Mbps`,
  constrained-underlay baseline `130.1/131.2 Mbps` with load
  `129.1/128.4 Mbps`, worker-pressure baseline `124.7/123.0 Mbps` with load
  `122.8/122.0 Mbps`, and rx-maintenance baseline `2153.2/2229.2 Mbps` with
  load `2264.2/2237.9 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `a358faf7df417bde52f4ff9fefbe336d8937e3d9999d49c36bdb119e6ee56502`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `685c852` makes peer-runtime route/send planning an owned boundary.
  `PipelinedEndpointPeerRuntimeRoute` now carries the captured
  `PeerRuntimeRouteSnapshot` together with path MTU, default TTL, scheduling
  weight, and direct-path bulk-drop policy. It builds the route plan and
  runtime send plan as one handoff, so `Node` prepares one peer-runtime route
  and consumes it instead of separately assembling route plan, send plan, and
  peer snapshot. The guard
  `pipelined_endpoint_peer_runtime_route_owns_snapshot_route_policy_and_send_plan`
  failed first because the owner did not exist, then passed. Verification
  passed: focused guard, `pipelined`, previous route-snapshot,
  `peer_lifecycle_registry_owns`, `session_registry_owns`, default local
  ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`173` tests), warning-clean release check, `cargo fmt`, bash syntax
  check, diff check, and private-string scan.
  Because this touches the pipelined endpoint/FSP send hot path, it got an
  exact short local-FIPS Docker perf checkpoint at nvpn `3d3780aa` plus FIPS
  `685c852`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/685c852-short-smoke-20260609Tpeer-runtime-route-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-685c852-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2195.1/2196.5 Mbps` with load `2244.5/2105.5 Mbps`,
  constrained-underlay baseline `130.3/132.0 Mbps` with load
  `129.8/130.2 Mbps`, worker-pressure baseline `131.3/129.4 Mbps` with load
  `127.8/129.1 Mbps`, and rx-maintenance baseline `2192.3/2299.1 Mbps` with
  load `2278.0/2238.3 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `9a0a82999e31f68479f2190acdd60bc1e0134c66db4eb3c40e9412ea76c3c463`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `4886c47` makes the pipelined endpoint runtime send attempt an owned
  boundary. `PipelinedEndpointRuntimeSendAttempt` carries the resolved send
  target plus runtime send plan and owns the FSP/FMP reservation handoff. The
  guard `pipelined_endpoint_runtime_send_attempt_owns_target_and_reservations`
  failed first because the owner did not exist, then passed. It verifies the
  happy path reserves both counters exactly once and the unavailable-FMP-worker
  path returns `None` without consuming additional session or peer counters.
  Verification passed: focused guard, `pipelined`, `peer_lifecycle_registry_owns`,
  `session_registry_owns`, broad local `unit` (`173` tests), default local
  ownership fast tier, focused Linux Docker ownership slice, warning-clean
  release check, `cargo fmt`, bash syntax check, diff check, and private-string
  scan. Because this touches the pipelined endpoint/FSP send hot path, it got
  an exact short local-FIPS Docker perf checkpoint at nvpn `cfcd36c2` plus FIPS
  `4886c47`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/4886c47-short-smoke-20260609Truntime-send-attempt \
PROJECT_NAME=nostr-vpn-e2e-fips-4886c47-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2201.5/2280.3 Mbps` with load `2226.8/2222.7 Mbps`,
  constrained-underlay baseline `131.5/129.7 Mbps` with load
  `128.3/128.5 Mbps`, worker-pressure baseline `128.3/122.3 Mbps` with load
  `127.8/128.5 Mbps`, and rx-maintenance baseline `2235.6/2232.5 Mbps` with
  load `2290.1/2286.3 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `bfcde4ec579ce1d9d5633e7e18eb28f294791d0142dfc0613da308752de5e0cb`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `ca694b0` makes the pipelined endpoint runtime send dispatch an owned
  boundary. `PipelinedEndpointRuntimeSend` carries the runtime send plan, owns
  transport lookup plus UDP send-target resolution, and delegates the FSP/FMP
  reservation handoff to `PipelinedEndpointRuntimeSendAttempt`. The guard
  `pipelined_endpoint_runtime_send_owns_transport_target_and_reservation_handoff`
  failed first because the owner did not exist, then passed. It verifies the
  happy path resolves transport/target and reserves both counters exactly once,
  and the missing-transport path fails before consuming additional session or
  peer counters. Verification passed: focused guard, `pipelined`,
  `peer_lifecycle_registry_owns`, `session_registry_owns`, broad local `unit`
  (`173` tests), default local ownership fast tier, focused Linux Docker
  ownership slice, warning-clean release check, `cargo fmt`, diff check, and
  private-string scan. Because this touches the pipelined endpoint/FSP send hot
  path, it got an exact short local-FIPS Docker perf checkpoint at nvpn
  `e864a3a1` plus FIPS `ca694b0`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/ca694b0-short-smoke-20260609Truntime-send-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-ca694b0-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2309.9/2283.6 Mbps` with load `2258.0/2243.6 Mbps`,
  constrained-underlay baseline `129.0/130.0 Mbps` with load
  `128.2/130.0 Mbps`, worker-pressure baseline `139.3/140.2 Mbps` with load
  `125.1/130.7 Mbps`, and rx-maintenance baseline `2240.8/2206.1 Mbps` with
  load `2197.5/2238.5 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `4902cab636db32a8fa17b13000322d41e78b96e28c27affbd20f3c975b5356c2`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `2871149` makes peer-runtime route choice an owned decision boundary.
  `PeerRuntimeRouteDecision` carries next-hop selection, peer-route snapshot
  capture, configured send weight, and direct-path bulk-drop eligibility
  together. `PipelinedEndpointPeerRuntimeRouteRequest` consumes that decision
  instead of interleaving route lookup, active-peer snapshot reads, route config,
  and direct-path policy inline. The guard
  `peer_runtime_route_decision_owns_next_hop_snapshot_weight_and_policy` failed
  first because the boundary did not exist, then passed. Verification passed:
  focused guard, `peer_runtime_route`, `pipelined`, broad local `unit`
  (`174` tests), default local ownership fast tier, focused Linux Docker
  ownership slice, warning-clean release check, `cargo fmt`, diff check, and
  private-string scan. Because this touches the pipelined endpoint/FSP route
  decision hot path, it got an exact short local-FIPS Docker perf checkpoint at
  nvpn `10849b8e` plus FIPS `2871149`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/2871149-short-smoke-20260609Troute-decision-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-2871149-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2299.7/2294.0 Mbps` with load `2253.2/2256.4 Mbps`,
  constrained-underlay baseline `127.6/128.3 Mbps` with load
  `132.6/133.8 Mbps`, worker-pressure baseline `130.5/126.8 Mbps` with load
  `126.3/130.3 Mbps`, and rx-maintenance baseline `2304.4/2258.3 Mbps` with
  load `2187.9/2259.7 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `a0a60dc1f7c643577a8b0fa5f0dde8eab72fff003281990cb316080c24b6d8a1`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `e8d42c7` makes endpoint/FSP send enter the peer-runtime owner through
  one `Node` facade. `Node::execute_peer_runtime_endpoint_send` now owns the
  transition from endpoint payload send into route decision, UDP target
  resolution, FSP/FMP reservation, and prepared worker-job commit, while the
  existing narrower peer-runtime types still own their individual steps. The
  guard `peer_runtime_endpoint_send_facade_owns_route_dispatch_and_commit`
  failed first because the facade did not exist, then passed. Verification
  passed: focused red-first guard, `peer_runtime`, `pipelined`, broad local
  `unit` (`174` tests), default local ownership fast tier, focused Linux Docker
  ownership slice, warning-clean release check, `cargo fmt`, diff check, and
  private-string scan. Because this touches the endpoint/FSP send hot path, it
  got an exact short local-FIPS Docker perf checkpoint at nvpn `6ede678e` plus
  FIPS `e8d42c7`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/e8d42c7-short-smoke-20260609Tendpoint-send-facade \
PROJECT_NAME=nostr-vpn-e2e-fips-e8d42c7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2265.0/2223.4 Mbps` with load `2216.6/2247.7 Mbps`,
  constrained-underlay baseline `130.1/131.2 Mbps` with load
  `133.4/133.4 Mbps`, worker-pressure baseline `127.9/129.8 Mbps` with load
  `128.4/128.2 Mbps`, and rx-maintenance baseline `2297.0/2210.0 Mbps` with
  load `2238.4/2330.6 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `3803e015e348ae459b194c14fd5ed6ac080fc2926bfdcebed6fc00d79f189aaf`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `534beee` makes the session datagram runtime route an owned boundary.
  `SessionDatagramRuntimeRoute` now owns next-hop resolution output,
  datagram path-MTU writes, source-side MMP path-MTU seeding, route-failure
  marking, outbound next-hop recording, and forwarding-originated stats for the
  encrypted link-send path. `Node::send_session_datagram` resolves that owner,
  performs the encrypted send, and then consumes the owner for success/failure
  bookkeeping instead of interleaving route, MMP, send, and stats decisions
  inline. The guard
  `session_datagram_runtime_route_owns_next_hop_path_mtu_and_bookkeeping`
  failed first because the runtime-route owner did not exist, then passed.
  Verification passed: focused guard, `session_datagram`, broad local `_own`
  (`78` tests), broad local `unit` (`174` tests), default local ownership fast
  tier, focused Linux Docker ownership slice, warning-clean release check,
  `cargo fmt`, diff check, and private-string scan. Because this touches the
  session datagram link-send hot path, it got an exact short local-FIPS Docker
  perf checkpoint at nvpn `34a40938` plus FIPS `534beee`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/534beee-short-smoke-20260609Tsession-datagram-route \
PROJECT_NAME=nostr-vpn-e2e-fips-534beee-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2235.2/2168.9 Mbps` with load `2286.5/2213.5 Mbps`,
  constrained-underlay baseline `127.0/129.6 Mbps` with load
  `131.1/132.7 Mbps`, worker-pressure baseline `133.0/127.8 Mbps` with load
  `130.7/127.4 Mbps`, and rx-maintenance baseline `2211.1/2067.6 Mbps` with
  load `2196.9/2226.3 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `9d83f0542ed61faee0a870b9920aec59023956e0aae379283f7475500610e1f9`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `12c775a` makes non-worker FSP send construction an owned boundary.
  `SessionFspSendPlan` owns FSP flags, optional source/destination coords,
  inner plaintext, timestamp, and data/control bookkeeping; it derives the CP
  flag from coords presence instead of leaving that rule to each call site.
  `SealedSessionFspSend` owns the reserved counter, ciphertext length, final
  FSP payload, and bookkeeping before datagram assembly. `Node` now sends
  service data, endpoint fallback, session-control messages, and coords warmup
  through `send_session_fsp_plan`, which seals, sends the session datagram, and
  records FSP bookkeeping only after send success. The guard
  `session_fsp_send_plan_owns_flags_coords_wire_and_bookkeeping` failed first
  because the plan/bookkeeping owner did not exist, then passed. Verification
  passed: focused guard, `session_datagram`, broad local `_own` (`79` tests),
  broad local `session` (`227` tests), broad local `endpoint` (`50` tests),
  broad local `unit` (`174` tests), default local ownership fast tier, focused
  Linux Docker ownership slice, warning-clean release check, `cargo fmt`, diff
  check, and private-string scan. Because this touches the non-worker FSP send
  hot path, it got an exact short local-FIPS Docker perf checkpoint at nvpn
  `42f13785` plus FIPS `12c775a`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/12c775a-short-smoke-20260609Tsession-fsp-send-plan \
PROJECT_NAME=nostr-vpn-e2e-fips-12c775a-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2223.2/2280.3 Mbps` with load `2246.3/2205.6 Mbps`,
  constrained-underlay baseline `127.4/136.1 Mbps` with load
  `132.7/132.9 Mbps`, worker-pressure baseline `119.3/130.2 Mbps` with load
  `130.0/124.0 Mbps`, and rx-maintenance baseline `2245.9/2260.5 Mbps` with
  load `2198.2/2188.6 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `47fc4d8e9930929cac8055e7b8ef2ed9340d6640a73cb9c6530c159b30911b95`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is the latest exact short checkpoint and remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `62249d0` makes peer-runtime send request execution an owned boundary.
  `PipelinedEndpointPeerRuntimeSendRequest::execute` resolves dispatch and
  commits the prepared worker job, so the request owns FSP/FMP counter
  reservation, session traffic bookkeeping, outbound next-hop recording, peer
  link send stats, and forwarding originated counters. `Node` now awaits the
  request result instead of owning the commit sequence after route resolution.
  The guard
  `pipelined_endpoint_peer_runtime_send_request_owns_commit_bookkeeping`
  failed first because `execute` did not exist, then passed. Verification
  passed: focused guard, `pipelined`, `peer_lifecycle_registry_owns`,
  `session_registry_owns`,
  `peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs`, broad
  local `unit` (`173` tests), default local ownership fast tier, focused Linux
  Docker ownership slice, warning-clean release check, `cargo fmt`, diff check,
  and private-string scan. Because this touches the pipelined endpoint/FSP send
  hot path, it got an exact short local-FIPS Docker perf checkpoint at nvpn
  `ba10816a` plus FIPS `62249d0`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/62249d0-short-smoke-20260609Tsend-execution-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-62249d0-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2256.2/2228.2 Mbps` with load `2235.3/2166.2 Mbps`,
  constrained-underlay baseline `130.6/130.2 Mbps` with load
  `133.1/131.9 Mbps`, worker-pressure baseline `132.7/131.5 Mbps` with load
  `124.9/130.1 Mbps`, and rx-maintenance baseline `2216.2/2249.0 Mbps` with
  load `2188.5/2281.0 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `334683239154443580b96caea59910b4ae3743a553264d5c79d5e527db3ff246`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `b889083` makes the peer-runtime send request an owned boundary.
  `PipelinedEndpointPeerRuntimeSendRequest` carries the endpoint send plus
  route request, resolves next-hop/snapshot/policy, and then owns dispatch
  preparation through runtime send planning, UDP target resolution, and FSP/FMP
  reservation handoff. `Node` now constructs one request and commits the
  prepared dispatch instead of sequencing route resolution and peer-runtime send
  dispatch separately. The guard
  `pipelined_endpoint_peer_runtime_send_request_owns_route_request_and_dispatch`
  failed first because the send-request owner and typed request error did not
  exist, then passed. It verifies the happy path captures a configured direct
  route, derives path MTU from the resolved UDP transport, reserves exactly one
  FSP counter and one FMP counter, and returns a typed route error for a
  missing destination. Verification passed: focused guard, `pipelined`,
  `peer_lifecycle_registry_owns`, `session_registry_owns`,
  `peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs`, broad
  local `unit` (`173` tests), default local ownership fast tier, focused Linux
  Docker ownership slice, warning-clean release check, `cargo fmt`, diff check,
  and private-string scan. Because this touches the pipelined endpoint/FSP send
  hot path, it got an exact short local-FIPS Docker perf checkpoint at nvpn
  `a31bef33` plus FIPS `b889083`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/b889083-short-smoke-20260609Tsend-request-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-b889083-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2207.4/2254.1 Mbps` with load `2214.2/2185.8 Mbps`,
  constrained-underlay baseline `128.4/132.4 Mbps` with load
  `130.7/131.1 Mbps`, worker-pressure baseline `128.5/127.2 Mbps` with load
  `127.9/128.1 Mbps`, and rx-maintenance baseline `2296.6/2221.6 Mbps` with
  load `2203.6/2294.0 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `27de17d6db64d7099b59a9a5c83251e5bcceff32a6422af178bb380bc11269f3`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker
  evidence, not real Mac-to-Mac validation.
- FIPS `0e70c02` makes the peer-runtime route request an owned boundary.
  `PipelinedEndpointPeerRuntimeRouteRequest` carries the source, destination,
  default TTL, and decision time, resolves the next hop, asks
  `PeerLifecycleRegistry` for the captured peer-route snapshot, applies
  configured send weight, and turns direct-path degradation into explicit
  bulk-drop policy. `Node` no longer interleaves next-hop lookup, active peer
  snapshot reads, route config, and direct-path policy while preparing the
  pipelined endpoint/FSP send handoff. The guard
  `pipelined_endpoint_peer_runtime_route_request_owns_next_hop_snapshot_and_policy`
  failed first because the route-request owner and typed request error did not
  exist, then passed. It verifies the happy path captures next hop, peer-route
  snapshot transport id, configured send weight, default TTL, and direct-path
  bulk policy, and that a missing route returns a typed `NoRoute` error.
  Verification passed: focused guard, `pipelined`,
  `peer_lifecycle_registry_owns`, `session_registry_owns`,
  `peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs`, broad
  local `unit` (`173` tests), default local ownership fast tier, focused Linux
  Docker ownership slice, warning-clean release check, `cargo fmt`, diff check,
  and private-string scan. Because this touches the pipelined endpoint/FSP send
  hot path, it got an exact short local-FIPS Docker perf checkpoint at nvpn
  `fe80aa8a` plus FIPS `0e70c02`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/0e70c02-short-smoke-20260609Troute-request-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-0e70c02-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2287.5/2309.1 Mbps` with load `2166.1/2230.4 Mbps`,
  constrained-underlay baseline `127.7/127.7 Mbps` with load
  `131.9/132.2 Mbps`, worker-pressure baseline `127.4/127.0 Mbps` with load
  `120.1/129.1 Mbps`, and rx-maintenance baseline `2241.4/2278.8 Mbps` with
  load `2132.2/2240.2 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `f4b4a2f2f28fb8b4d4922fb05b980308558baa814b14474e0487fae3c778202c`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `c043dd7` moves peer-runtime path-MTU ownership into the send facade.
  `PipelinedEndpointPeerRuntimeRoute` now carries the captured peer-route
  snapshot plus default TTL, scheduling weight, and direct-path bulk-drop
  policy, while `PipelinedEndpointPeerRuntimeSend` resolves the selected
  transport and derives path MTU from the transport/current-address pair before
  building the runtime send plan. `Node` no longer peeks into the transport map
  to precompute path MTU for the pipelined endpoint send path. The guard
  `pipelined_endpoint_peer_runtime_send_owns_transport_path_mtu_route_plan_and_runtime_dispatch`
  failed first on the old constructor/API, then passed. It verifies the happy
  path derives the FSP reservation path MTU from the selected transport,
  reserves both counters exactly once, and still fails missing transports
  before consuming additional session or peer counters. Verification passed:
  focused guard, `pipelined`, `peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs`,
  `peer_lifecycle_registry_owns`, `session_registry_owns`, broad local `unit`
  (`173` tests), default local ownership fast tier, focused Linux Docker
  ownership slice, warning-clean release check, `cargo fmt`, diff check, and
  private-string scan. Because this touches the pipelined endpoint/FSP send hot
  path, it got an exact short local-FIPS Docker perf checkpoint at nvpn
  `bf325005` plus FIPS `c043dd7`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/c043dd7-short-smoke-20260609Tpath-mtu-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-c043dd7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2249.2/2205.6 Mbps` with load `2291.4/2217.0 Mbps`,
  constrained-underlay baseline `128.1/131.6 Mbps` with load
  `132.1/132.8 Mbps`, worker-pressure baseline `122.9/129.4 Mbps` with load
  `132.3/129.0 Mbps`, and rx-maintenance baseline `2166.9/2212.3 Mbps` with
  load `2289.1/2172.3 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `70a2f9a3daecfc3b7aeed8525e94bc60dee5a42974c88dc1344f23bc778c972f`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `f3d28ab` makes the pipelined endpoint peer-runtime send dispatch an
  owned boundary. `PipelinedEndpointPeerRuntimeSend` carries the original
  endpoint send plus peer-runtime route, owns runtime send-plan construction,
  and delegates transport lookup, UDP target resolution, and FSP/FMP
  reservation handoff to `PipelinedEndpointRuntimeSend`. The guard
  `pipelined_endpoint_peer_runtime_send_owns_route_plan_and_runtime_dispatch`
  failed first because the owner did not exist, then passed. It verifies the
  happy path builds the runtime plan, resolves transport/target, and reserves
  both counters exactly once; it also verifies the missing-transport path fails
  before consuming additional session or peer counters. Verification passed:
  focused guard, `pipelined`, `peer_lifecycle_registry_owns`,
  `session_registry_owns`, broad local `unit` (`173` tests), default local
  ownership fast tier, focused Linux Docker ownership slice, warning-clean
  release check, `cargo fmt`, diff check, and private-string scan. Because this
  touches the pipelined endpoint/FSP send hot path, it got an exact short
  local-FIPS Docker perf checkpoint at nvpn `a2c71ace` plus FIPS `f3d28ab`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_DURATION_SECS=2 \
NVPN_PERF_LOAD_DURATION_SECS=3 \
NVPN_PERF_PING_COUNT=8 \
NVPN_PERF_CONSTRAINED_RATE_MBIT=180 \
NVPN_PERF_WORKER_QUEUE_PRESSURE_CAP=4 \
NVPN_PERF_RX_MAINT_FAULT_MS=50 \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/f3d28ab-short-smoke-20260609Tpeer-runtime-send-owner \
PROJECT_NAME=nostr-vpn-e2e-fips-f3d28ab-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay baseline roughly
  `2310.3/2229.3 Mbps` with load `2220.8/2198.3 Mbps`,
  constrained-underlay baseline `129.6/129.7 Mbps` with load
  `129.2/130.5 Mbps`, worker-pressure baseline `120.6/126.6 Mbps` with load
  `128.1/121.4 Mbps`, and rx-maintenance baseline `2231.7/2229.7 Mbps` with
  load `2218.9/2131.2 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct
  UDP counters advanced in every phase, worker pressure exposed expected
  decrypt queue-full/bulk-drop counters, and `failure-summary.tsv` contained
  only the header. Phase summary hash:
  `1f54df01b7e3c6c759b5111d226e43727b211039b5e2d02995fe0765fb8cbfbe`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is an earlier exact short checkpoint and remains Linux/Docker evidence,
  not real Mac-to-Mac validation.
- FIPS `10fdb8a` makes pipelined endpoint send-target resolution an owned
  boundary. `PipelinedEndpointSendTarget::resolve` owns connected-UDP
  preference, fallback remote-address resolution, async UDP socket
  availability, and selected-target handoff. Connected sockets win without
  resolving the fallback address; wildcard UDP still resolves the prepared
  fallback address. `try_send_session_endpoint_data_pipelined` still sequences
  route lookup, peer/session reservation ordering, FMP/FSP bookkeeping owners,
  dispatch-plan construction, and worker dispatch. The guard
  `pipelined_endpoint_send_target_owns_connected_udp_preference_and_fallback`
  failed first because the owner did not exist, then passed.
  Verification passed: focused guard, adjacent `pipelined`,
  `session_registry_owns`, `fmp_worker`, and `connected_udp` filters, default
  local ownership fast tier, focused Linux Docker ownership slice, broad local
  `unit` (`171` tests), release check, `cargo fmt --check`, bash syntax check,
  diff check, and private-string scan with a harmless `.local_addr()` false
  positive.
  Because this touches connected-UDP/path target selection on the pipelined
  endpoint/FSP send hot path, an exact short local-FIPS Docker perf checkpoint
  at nvpn `0c9e65c8` plus FIPS `10fdb8a` passed all four phases:
  clean-underlay baseline roughly `2264.2/2295.0 Mbps` with load
  `2057.2/2196.1 Mbps`, constrained-underlay baseline `131.7/133.2 Mbps` with
  load `129.3/127.7 Mbps`, worker-pressure baseline `126.2/128.1 Mbps` with
  load `121.8/127.7 Mbps`, and rx-maintenance baseline `2183.3/2219.1 Mbps`
  with load `2181.8/2219.6 Mbps`. Load/post tunnel-ping loss stayed `0%`,
  direct UDP counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. Phase summary hash:
  `2b8bc98ecf7622ff3daf375c77bb80d9abad2e7a5791e4848d02db92db806611`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- nvpn `d5a672ec` plus the FIPS mesh prefix-route-index diff keeps exact peer
  routes in the existing O(1) ambiguity-preserving index and builds separate
  IPv4/IPv6 fallback indexes only for non-exact routes. Fallback lookup scans
  longest prefixes first, stops after lower prefixes cannot beat the current
  winner, and still drops equal-prefix ambiguity between different
  participants. The guard
  `fallback_prefix_index_skips_exact_routes_and_preserves_longest_prefix` is
  included in the `core` fast tier. Verification passed with format check, the
  focused `nostr-vpn-core fips_mesh` test filter, bash syntax, the `core` fast
  tier, `cargo check -p nostr-vpn-core --release`, and `git diff --check`.
  Because this changes route lookup for default/exit traffic, it got a local
  FIPS Docker smoke with FIPS `0846db7`:

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/nvpn-prefix-route-index-fips-0846db7-smoke \
./scripts/e2e-fips-perf-regression-docker.sh
```

  It passed all four phases: clean-underlay `2674.4/2580.9 Mbps` with load
  `2638.9/2606.5 Mbps`, constrained-underlay `172.3/173.9 Mbps` with load
  `174.2/174.3 Mbps`, worker-pressure `230.9/231.3 Mbps` with load
  `231.9/230.1 Mbps`, and rx-maintenance `2619.0/2609.2 Mbps` with load
  `2646.6/2595.2 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct UDP
  counters advanced in every phase, worker pressure exposed expected
  queue-full/drop counters, and `failure-summary.tsv` contained only the
  header. Phase summary hash:
  `3dd0f33194cf4667dcdce43312db736301d3bd23901767e74f3591278a97a446`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  The remaining high-rate reverse-side hotspot is still
  `fmp_worker_queue_wait` around `176.7us` clean and `181.7us` under
  rx-maintenance, so the next performance slice should target the FIPS worker
  handoff/ordered send path rather than another nvpn route-table scan. This
  remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `d5404a6` makes the non-macOS encrypt-worker drain batch tunable with
  `FIPS_WORKER_BATCH`, keeps non-Linux Unix at `32`, and moves Linux to a
  default `48`. The parser clamps to `1..=64`, matching the Linux UDP_GSO
  helper's maximum submitted iovec count so same-target groups cannot account
  more packets than the GSO send path can submit. nvpn's `fips` fast selector
  now includes
  `worker_batch_size_parse_stays_within_sender_accounting_limit`.

```sh
NVPN_PATCH_LOCAL_FIPS=1 \
NVPN_FIPS_REPO_PATH=/path/to/fips-dataplane-safety \
NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/worker-batch-48-full \
PROJECT_NAME=nostr-vpn-worker-batch-48-full \
./scripts/e2e-fips-perf-regression-docker.sh
```

  The default-env Docker smoke passed all four phases: clean-underlay
  `2552.0/2440.8 Mbps` with load `2490.6/2532.8 Mbps`,
  constrained-underlay `164.2/164.0 Mbps` with load `165.8/165.3 Mbps`,
  worker-pressure `231.8/228.9 Mbps` with load `229.5/228.2 Mbps`, and
  rx-maintenance `2583.9/2629.2 Mbps` with load `2571.8/2586.3 Mbps`.
  Load/post tunnel-ping loss stayed `0%`, direct UDP counters advanced in
  every phase, worker pressure exposed expected decrypt queue-full/drop
  counters, and `failure-summary.tsv` contained only the header. Phase summary
  hash: `3d68b13277a693bb1afe878030a56150f06d5a15b93e66846797ad03f3144b25`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  A `64` default probe at `artifacts/fips-perf/worker-batch-64-clean-rx`
  passed thresholds but collapsed clean/rx throughput to roughly `1.2 Gbps`
  with heavy retransmits, so `64` is rejected. The accepted `48` default lowers
  the receive-heavy clean/rx `fmp_worker_queue_wait` band versus the route-index
  smoke without claiming the queue work is done; endpoint/transport/event queue
  residence is still visible in the hundreds of microseconds under clean/rx
  high packet rate. This remains Linux/Docker evidence, not real Mac-to-Mac
  validation.
- FIPS `9ab39ea` removes per-packet clock reads from the UDP receive batch
  boundary by adding an internal `ReceivedPacket::with_trace_timestamp`
  constructor and sharing one wall-clock receive timestamp plus one pipeline
  queue stamp across each drained batch. Focused local checks passed:
  `cargo fmt --check`, `git diff --check`,
  `cargo check -p fips-core --release`,
  `cargo test -p fips-core received_packet_can_reuse_batch_timestamps`, and
  `cargo test -p fips-core drain_delivers_packets_to_packet_tx`. A focused
  clean/rx Docker smoke at
  `artifacts/fips-perf/udp-batch-timestamp-clean-rx` passed with
  clean-underlay `2691.7/2692.8 Mbps` baseline and `2604.6/2644.0 Mbps`
  under load, rx-maintenance `2663.1/2654.1 Mbps` baseline and
  `2611.8/2680.1 Mbps` under load, `0%` load/post ping loss, phase hash
  `0df6260514b00d53f0f247790a4190a18583193ba7cd118bfb9d51d76fdebb9f`, and
  failure hash
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  The default-env full Docker smoke at
  `artifacts/fips-perf/udp-batch-timestamp-full` also passed all four phases:
  clean-underlay `2641.5/2597.1 Mbps` with load `2617.9/2653.0 Mbps`,
  constrained-underlay `167.1/166.1 Mbps` with load `165.2/166.1 Mbps`,
  worker-pressure `232.2/229.5 Mbps` with load `230.0/231.3 Mbps`, and
  rx-maintenance `2640.2/2668.4 Mbps` with load `2624.3/2618.6 Mbps`.
  Load/post tunnel-ping loss stayed `0%`, direct UDP counters advanced in
  every phase, worker pressure exposed only expected decrypt queue-full/drop
  counters, and `failure-summary.tsv` contained only the header. Full-smoke
  phase summary hash:
  `bb540d4a07ee576090ca7a2bd60e50e0cc847eb3820ea3e1b555b952f1f6cc98`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  Reducing the nvpn mesh receive burst to `64` and `32` was rejected: both
  targeted clean/rx probes passed liveness thresholds, but `64` did not improve
  high-rate `endpoint_event_wait` and `32` made it worse, so no nvpn tuning
  knob was kept. Endpoint/transport/event queue residence remains the next
  visible bottleneck. This remains Linux/Docker evidence, not real Mac-to-Mac
  validation.
- FIPS `cb2d944` introduces `PeerRuntimeReceive`, the first receive-side
  peer-runtime boundary for authenticated FMP plaintext. It parses the inner
  timestamp, owns the receive metadata and lifecycle bookkeeping handoff, and
  returns dispatch metadata to the existing rx-loop hook. This keeps the
  current decrypt-worker bounce semantics while creating a concrete owner for
  the later endpoint-data fast path. Focused local checks passed:
  `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core peer_runtime_receive`,
  `cargo test -p fips-core peer_lifecycle_registry_owns_authenticated_fmp_receive_bookkeeping`,
  `cargo test -p fips-core authenticated_lower_priority_packet_does_not_rotate_configured_static_path`,
  and `cargo check -p fips-core --release`. The default-env full Docker run
  with nvpn `2320c727` and local FIPS patch
  `NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/cb2d944-peer-runtime-receive-full`
  passed all four phases: clean-underlay `2620.9/2557.3 Mbps` with load
  `2610.0/2572.3 Mbps`, constrained-underlay `162.4/163.1 Mbps` with load
  `164.5/165.5 Mbps`, worker-pressure `233.3/233.0 Mbps` with load
  `228.9/231.8 Mbps`, and rx-maintenance `2652.8/2630.4 Mbps` with load
  `2626.7/2612.1 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct UDP
  counters advanced in every phase, worker pressure exposed only expected
  decrypt queue-full/drop counters, and `failure-summary.tsv` contained only
  the header. Phase summary hash:
  `3371d4abc1211b5630036bd7d2262e1927b289406ec7ac081e94fa2a4b778756`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is accepted architecture cleanup, not a throughput optimization; the
  next larger slice should move endpoint-data delivery behind a peer/shard
  runtime owner and delete the rx-loop bounce only with before/after safety
  evidence. This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `22f9dbf` moves endpoint-event sender, rx-loop batch scope, and backlog
  accounting into one `EndpointEventRuntime`, leaving `Node` as the facade for
  existing rx-loop call sites. This is the delivery-side owner needed before a
  future peer/shard runtime can move endpoint-data delivery out of the rx-loop
  bounce path. Focused local checks passed: `cargo fmt --check`,
  `git diff --check`, `cargo test -p fips-core endpoint_event_runtime`,
  `cargo test -p fips-core endpoint_event_batch_scope`,
  `cargo test -p fips-core endpoint_event_queue_owns_backlog_message_count`,
  `cargo test -p fips-core endpoint`,
  `cargo test -p fips-core node::tests::session`, and
  `cargo check -p fips-core --release`. The default-env full Docker run with
  nvpn `034bab8b` and local FIPS patch
  `NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/22f9dbf-endpoint-event-runtime-full`
  passed all four phases: clean-underlay `2688.4/2570.2 Mbps` with load
  `2656.4/2640.5 Mbps`, constrained-underlay `166.0/163.7 Mbps` with load
  `165.5/164.1 Mbps`, worker-pressure `234.5/232.6 Mbps` with load
  `231.3/228.6 Mbps`, and rx-maintenance `2629.9/2699.0 Mbps` with load
  `2653.3/2679.5 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct UDP
  counters advanced in every phase, worker pressure exposed only expected
  decrypt queue-full/drop counters, and `failure-summary.tsv` contained only
  the header. Phase summary hash:
  `f6dda023104ebcf3bbbb899f54b55551e5c554e505b61e39dee28a33a96c296b`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is accepted delivery-ownership cleanup with neutral same-harness perf,
  not a throughput optimization; high-rate clean/rx-maintenance still show
  endpoint-event wait in the hundreds of microseconds on the receive-heavy
  side. This remains Linux/Docker evidence, not real Mac-to-Mac validation.
- FIPS `5721357` introduces `SessionRuntimeReceive`, the receive-side FSP
  owner for established session frames. It owns open/replay, K-bit epoch
  cutover, decrypt-failure recovery gating, MMP receive/path-MTU bookkeeping,
  authenticated remote identity lookup, and the dispatch metadata returned to
  the post-borrow session handler. Focused local checks passed: `cargo fmt
  --check`, `git diff --check`,
  `cargo test -p fips-core session_runtime_receive`,
  `cargo test -p fips-core node::handlers::session`,
  `cargo test -p fips-core endpoint`,
  `cargo test -p fips-core node::tests::session`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core` (`1504` passed, `2` ignored; doctests `2`
  ignored). nvpn local-FIPS checks passed:
  `cargo test -p nvpn endpoint_data_runtime_sends_and_receives_raw_packet_batch --features embedded-fips`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips` (`59`
  passed). The default-env full Docker run with nvpn `941cefd1` and local FIPS
  patch `NVPN_PERF_OUTPUT_DIR=artifacts/fips-perf/session-runtime-receive-full`
  passed all four phases: clean-underlay `2686.7/2665.1 Mbps` with load
  `2676.0/2708.4 Mbps`, constrained-underlay `166.5/167.0 Mbps` with load
  `166.9/165.7 Mbps`, worker-pressure `231.9/233.5 Mbps` with load
  `233.6/235.1 Mbps`, and rx-maintenance `2664.0/2721.9 Mbps` with load
  `2674.4/2653.9 Mbps`. Load/post tunnel-ping loss stayed `0%`, direct UDP
  counters advanced in every phase, worker pressure exposed only expected
  decrypt queue-full/drop counters, and `failure-summary.tsv` contained only
  the header. Phase summary hash:
  `d7d20dfeb60af299d313995b61bb9ede5f71e034f06b6099d94d94e986dbbfe9`;
  failure summary hash:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  This is accepted FSP receive ownership cleanup with healthy same-harness
  perf, not a solved queue-residence issue; clean/rx-maintenance still show
  endpoint-event wait in the hundreds of microseconds on the receive-heavy
  side. The next endpoint-data fast-path rewrite should move FMP receive, FSP
  receive, and endpoint-event delivery under the same worker/shard owner before
  deleting the rx-loop bounce. This remains Linux/Docker evidence, not real
  Mac-to-Mac validation.
- FIPS `e524e14` tightens worker-owned receive state by replacing
  `OwnedSessionState::source_npub: Option<String>` with
  `source_peer: PeerIdentity` copied from the authenticated `ActivePeer` during
  decrypt-worker session registration. This keeps worker-owned state aligned
  with endpoint-event delivery without changing FMP/FSP packet semantics or
  removing the rx-loop bounce. Focused checks passed: `cargo fmt --check`,
  `git diff --check`,
  `cargo test -p fips-core owned_session_state_carries_authenticated_source_peer -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `cargo test -p nvpn endpoint_data_runtime_sends_and_receives_raw_packet_batch --features embedded-fips`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips` (`59`
  passed). No Docker perf rerun was taken because this was a registration-only
  ownership/type cleanup; the latest full Docker checkpoint remains nvpn
  `941cefd1` plus FIPS `5721357`.
- FIPS `1b20991` continues that source-peer cleanup through the decrypt-worker
  fallback path: `DecryptFallback` and `DecryptFailureReport` now carry the
  authenticated `source_peer: PeerIdentity`, and the hot `DecryptJob` no longer
  carries a raw `source_node_addr` solely for worker-to-rx echo. The rx loop
  still derives the node address at the processing edge and still owns
  FSP/session dispatch, so this preserves existing FMP-only worker bounce
  semantics while making the future endpoint-data direct-delivery event shape
  match `FipsEndpointMessage`. Focused checks passed: `cargo fmt --check`,
  `git diff --check`, `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `cargo test -p nvpn endpoint_data_runtime_sends_and_receives_raw_packet_batch --features embedded-fips`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips` (`59`
  passed). No Docker perf rerun was taken because no per-packet queueing,
  routing, crypto, sender, or delivery semantics changed; the latest full
  Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `b995327` makes the authenticated post-FMP receive boundary a single
  `AuthenticatedFmpPlaintext` envelope instead of loose node-address, transport,
  timestamp, length, counter, flag, and plaintext arguments. The envelope carries
  authenticated `source_peer: PeerIdentity`; `PeerRuntimeReceive` derives the
  source node address plus CE/SP flags from it, and worker fallback, pending
  K-bit cutover, and synchronous test-mode FMP receive all use the same typed
  boundary. This preserves current rx-loop FSP/session dispatch and endpoint
  delivery semantics while giving the future worker/shard runtime one receive
  object to consume directly. Focused checks passed: `cargo fmt --check`,
  `git diff --check`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core authenticated_lower_priority_packet_does_not_rotate_configured_static_path -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `12b9b53` extends the typed receive boundary into link dispatch:
  `PeerRuntimeReceiveDispatch` now turns non-empty authenticated link plaintext
  into an `AuthenticatedLinkMessage` carrying source peer, message type, payload,
  and CE flag, and `dispatch_link_message` consumes that envelope instead of
  loose node-address/raw-bytes/CE arguments. This preserves current rx-loop
  link/session dispatch behavior while keeping authenticated source identity
  attached through the next edge a future worker/shard runtime needs to own.
  Focused checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `a25bd87` carries the authenticated handoff through the SessionDatagram
  dispatch edge: `AuthenticatedLinkMessage::into_session_datagram` builds an
  `AuthenticatedSessionDatagram` with previous-hop peer identity, payload, and
  CE flag, and the forwarding/local-delivery handler consumes that object
  instead of loose previous-hop/raw-bytes/CE arguments. This preserves current
  rx-loop FSP receive, route learning, forwarding, and endpoint delivery
  behavior while keeping the previous-hop authentication fact attached to the
  exact boundary the future peer/session runtime must own. Focused checks
  passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `138661f` extends that typed handoff into local session payload delivery
  and established encrypted-FSP receive: `LocalSessionPayload` carries source
  node, authenticated previous-hop peer, payload, path MTU, and CE flag, then
  converts to `EncryptedSessionPayload` for the FSP open/replay edge. This
  preserves current rx-loop session setup, route learning, FSP receive,
  endpoint delivery, and CE-marking behavior while removing another loose
  source/payload/MTU/CE/previous-hop argument cluster from the future
  peer/session runtime boundary. Focused checks passed: `cargo fmt --check`,
  `git diff --check`, `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `fb278ad` carries the established FSP endpoint-data handoff into
  `EndpointDataDelivery`: the delivery object owns authenticated source peer
  plus payload, `EndpointEventRuntime::deliver_endpoint_data` consumes it, and
  embedded endpoint facade batch tests build the same object. This preserves
  endpoint event batching, backlog accounting, rx-loop dispatch, and the
  no-extra-allocation payload trim path while removing the loose source-peer/
  payload pair at the future runtime boundary. Focused checks passed:
  `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core endpoint_event_batch_scope -- --nocapture`,
  `cargo test -p fips-core endpoint_event_queue_owns_backlog_message_count -- --nocapture`,
  `cargo test -p fips-core recv_batch_into_splits_internal_endpoint_batches_without_reordering -- --nocapture`,
  `cargo test -p fips-core try_recv_drains_pending_internal_endpoint_batch_tail -- --nocapture`,
  `cargo test -p fips-core blocking_recv_drains_pending_internal_endpoint_batch_tail -- --nocapture`,
  `cargo test -p fips-core recv_batch_drains_ready_loopback_endpoint_data -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1505` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `b8f3471` carries successful established-FSP open output into
  `AuthenticatedSessionMessage`: source peer, plaintext, inner msg type, inner
  flags, and timestamp now move as one object from `SessionRuntimeReceive` into
  rx-loop dispatch. Endpoint-data conversion is owned by that object and still
  drains the FSP inner header in place before building `EndpointDataDelivery`.
  This preserves reverse-route learning, rx-loop dispatch, endpoint event
  delivery, and session recv/touch bookkeeping while removing another loose
  source/msg/plaintext argument cluster at the future runtime boundary. Focused
  checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1506` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, or delivery semantics changed;
  the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `f10a737` carries the authenticated established-FSP message plus local
  dispatch facts as `AuthenticatedSessionDispatch`: source node, authenticated
  previous-hop node, CE flag, and receive-completion bookkeeping now move
  together through the rx-loop dispatch edge. Reverse-route learning, rx-loop
  message dispatch, endpoint event delivery, CE propagation, session
  recv/touch, and pending flush behavior are intentionally unchanged; the new
  `receive_completion` owner only returns application data completions so MMP
  reports cannot reset idle timers or traffic counters. Focused checks passed:
  `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture`,
  `cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1507` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, batching, or delivery semantics
  changed; the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `0471231` extracts authenticated established-FSP local dispatch into
  `handle_authenticated_session_dispatch`, so route learning, message dispatch,
  endpoint delivery, receive accounting, and pending flush all consume the same
  `AuthenticatedSessionDispatch` object after FSP open/replay succeeds.
  `SessionDispatchCommit` owns the source peer whose pending packets are
  flushed and the optional receive completion used for application data only;
  MMP reports still flush pending packets without resetting idle timers or
  traffic counters. Focused checks passed: `cargo fmt --check`,
  `git diff --check`,
  `cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture`,
  `cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1507` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, batching, or delivery semantics
  changed; the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `47c7b85` moves the application-data receive counter/touch mutation
  behind `SessionDispatchCommit::record_receive`. `SessionDispatchCommit` now
  owns both the source peer whose pending packets are flushed and the optional
  receive completion that may update session activity. The guard proves
  EndpointData increments session receive counters and updates
  `last_activity`, while SenderReport/MMP dispatch still records no
  application-data receive progress. Focused checks passed: `cargo fmt
  --check`, `git diff --check`,
  `cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture`,
  `cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1507` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, batching, or delivery semantics
  changed; the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `40e3da7` moves the post-dispatch finalization sequence behind
  `SessionDispatchCommit::finalize`: application-data receive bookkeeping runs
  first when present, then pending outbound packets flush for the same
  authenticated source peer. `handle_authenticated_session_dispatch` now
  dispatches the authenticated session message and hands finalization to the
  commit owner, instead of open-coding receive bookkeeping plus pending flush
  after the message-type handlers. Focused checks passed: `cargo fmt --check`,
  `git diff --check`, `cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture`,
  `cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1507` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, batching, or delivery semantics
  changed; the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `29ab97f` moves local established-FSP message dispatch onto
  `AuthenticatedSessionDispatch::dispatch`: the authenticated dispatch envelope
  now consumes itself through reverse-route learning, message-type dispatch,
  and commit finalization. `Node::handle_encrypted_session_msg` now builds the
  dispatch object and hands it to the owner instead of calling a `Node` helper.
  Focused checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture`,
  `cargo test -p fips-core authenticated_session_message_owns_endpoint_delivery_conversion -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1507` passed, `2` ignored;
  doctests `2` ignored). nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`
  and `cargo test -p nvpn fips_private_mesh --features embedded-fips -- --nocapture`
  (`59` passed) using local FIPS patch config. No Docker perf rerun was taken
  because no queueing, routing, crypto, sender, batching, or delivery semantics
  changed; the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.
- FIPS `3fc0454` gives authenticated EndpointData its own straight-line hot
  branch through `dispatch_endpoint_data_fast` and
  `SessionDispatchCommit::finish_receive`. The authenticated owner still learns
  the reverse route, delivers endpoint data, records application-data receive
  progress, and flushes pending packets when the guard has queued traffic, but
  the common no-pending-traffic case skips the generic async dispatcher and
  avoids awaiting a no-op pending flush. Focused FIPS checks passed:
  `cargo fmt --check -p fips-core`, `git diff --check`,
  `cargo test -p fips-core endpoint_data_fast_dispatch_finishes_receive_without_pending_flush -- --nocapture`,
  `cargo test -p fips-core authenticated_session_dispatch_owns_route_ce_and_completion_facts -- --nocapture`,
  `cargo test -p fips-core session_runtime_receive -- --nocapture`,
  `cargo test -p fips-core node::handlers::session::tests:: -- --nocapture`,
  `cargo test -p fips-core endpoint -- --nocapture`, and
  `cargo check -p fips-core --release`. nvpn local-FIPS checks also passed:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh fips nvpn-hotpath`
  and release-shaped `cargo check -p nvpn --release --features embedded-fips`
  with local FIPS patch config. A focused Docker perf run at pre-doc nvpn
  `e59644b7` plus FIPS `3fc0454` passed
  `NVPN_PERF_PHASES=clean-underlay,rx-maintenance-fault` with `0%` load/post
  ping loss, an empty failure summary, and no raw matches for bulk drops or
  backlog-high counters. Results: clean-underlay `2684.3/2505.9 Mbps` with
  load `2702.0/2569.2 Mbps`, rx-maintenance-fault `2693.6/2585.1 Mbps` with
  load `2583.3/2574.2 Mbps`. Artifacts:
  `/tmp/nvpn-endpoint-fast-dispatch-perf-20260611-113131`;
  `phase-summary.tsv` SHA-256:
  `c883bd20d7f41ce2d5416df9b1d9e4874a015555bc961c458dd3f007ff02706a`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
  The remaining performance target is transport queue/channel residence, not
  endpoint-event delivery.
- FIPS `50349db` exposes the worker-to-rx-loop fallback residence that remained
  hidden after the decrypt worker intentionally bounced all link messages back to
  the rx loop. `DecryptWorkerFallbackSender` now stamps fallback events before
  enqueue; rx-loop dequeue records `decrypt_fallback_wait`,
  `decrypt_fallback_priority_wait`, and `decrypt_fallback_bulk_wait`. Focused
  FIPS checks passed: `cargo fmt --check -p fips-core`, `git diff --check`,
  `cargo test -p fips-core decrypt_worker_fallback -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core rx_loop -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`, and
  `cargo check -p fips-core --release`. nvpn harness/local-FIPS checks also
  passed: `bash -n` for the perf/soak harness scripts,
  `./scripts/test-fips-perf-harness.sh`, `./scripts/test-fips-soak-harness.sh`,
  `./scripts/test-host-pair-harness.sh`,
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh fips nvpn-hotpath`,
  and release-shaped `cargo check -p nvpn --release --features embedded-fips`
  with local FIPS patch config. A focused Docker perf run at pre-doc nvpn
  `c0eb6a9e` plus FIPS `50349db` passed
  `NVPN_PERF_PHASES=clean-underlay,rx-maintenance-fault` with `0%` load/post
  ping loss, an empty failure summary, no raw matches for bulk drops or
  backlog-high counters, and visible decrypt-fallback wait fields in the raw
  pipeline artifacts. Results: clean-underlay `2510.8/2546.6 Mbps` with load
  `2582.4/2535.0 Mbps`, rx-maintenance-fault `2541.4/2526.9 Mbps` with load
  `2510.0/2577.3 Mbps`. Artifacts:
  `/tmp/nvpn-decrypt-fallback-wait-perf-20260611-114958`;
  `phase-summary.tsv` SHA-256:
  `104488e542b006d09665042b24d9d627dd9929222da2794176bacb884d7d9bed`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`;
  `raw/host-start.txt` SHA-256:
  `63cba99018c90ad909b93771dc661a608b309d6e5234276e4234cd4c1422bb0a`;
  `raw/host-end.txt` SHA-256:
  `0b550877c5c4bebcd82e87818bd4a5fcb91a888d116a7f40940d5f583affef88`.
  The evidence points the next bottleneck back at transport queue/channel
scheduling: decrypt fallback waits stayed in the tens of microseconds on
average with sub-millisecond p99, while transport queue/channel waits still
entered millisecond p99/tail bands.
- A current-head short local-FIPS Docker smoke at nvpn `95d98162` plus FIPS
  `29ab97f` passed all four default phases after the receive-ownership batch.
  It used `NVPN_PERF_DURATION_SECS=2` and `NVPN_PERF_LOAD_DURATION_SECS=3`, so
  it is a freshness/liveness check rather than a replacement for the longer
  default-duration Docker checkpoint. Results: clean-underlay
  `2634.1/2654.8 Mbps` with load `2624.2/2550.0 Mbps`,
  constrained-underlay `158.4/155.8 Mbps` with load `166.2/166.9 Mbps`,
  worker-pressure `235.7/233.8 Mbps` with load `230.2/237.4 Mbps`, and
  rx-maintenance-fault `2585.5/2587.9 Mbps` with load
  `2620.1/2595.8 Mbps`. All load/post-load tunnel pings had `0%` loss and
  direct UDP bytes advanced in every phase. `phase-summary.tsv` SHA-256:
  `9175c07158f67c9492c77d89702972af948dc52233b7fdebc7a17b22b3dcba89`;
  `failure-summary.tsv` SHA-256:
  `d8992f9bc73cbfa74b1651bd8621dac5f37b9ac2e49426eca850bbb809caf214`.
- `scripts/e2e-fips-perf-regression-docker.sh` now writes the per-phase
  `node-a` / `node-b` pipeline tails it prints to console into raw artifacts
  when `NVPN_PERF_OUTPUT_DIR` is set. Verification passed: `bash -n
  scripts/e2e-fips-perf-regression-docker.sh scripts/test-fips-perf-harness.sh`,
  `./scripts/test-fips-perf-harness.sh`, and a focused local-FIPS
  worker-queue-pressure Docker smoke. The focused smoke passed with
  `232.1/238.1 Mbps` baseline, `233.3/238.0 Mbps` load, `0%/0%` load ping
  loss, post-load `0%` loss, direct UDP bytes `237984788/244569057`, and
  durable pipeline snapshot hashes
  `09cd541ac9c6299820330e822cdd9247a3e7dd5bb0f8b10ad34baa2e768b080a` plus
  `60ec0833e04f87b2bac862b77b23944ed1c3b78cea2693422b2c0f018aec5a14`.
- FIPS `bf00971` moves timeout-driven session handshake selection and resend
  bookkeeping behind `SessionRegistry`. The new guards
  `session_registry_owns_timeout_handshake_selection_and_resend_accounting` and
  `session_registry_owns_exhausted_established_handshake_cleanup` pin pending
  timeout selection, due-resend payload selection, successful resend backoff
  accounting, established resend-budget cleanup, and rekey abandonment. Focused
  checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core timeout -- --nocapture`,
  `cargo test -p fips-core node::tests::session -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1512` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing,
  crypto, sender, batching, or delivery semantics changed; the latest full
  Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `2bf6ab1` moves FSP rekey SessionMsg3 resend selection and accounting
  behind `SessionRegistry`. The new guards
  `session_registry_owns_rekey_msg3_resend_selection_and_accounting` and
  `session_registry_owns_exhausted_rekey_msg3_cleanup` pin due-msg3 payload
  selection, due-and-exhausted budget cleanup, successful resend backoff
  accounting, and pending rekey cleanup. Focused checks passed:
  `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core rekey -- --nocapture`,
  `cargo test -p fips-core node::tests::session -- --nocapture`,
  `cargo test -p fips-core timeout -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1514` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing, crypto, sender,
  batching, or delivery semantics changed; the latest full Docker checkpoint
  remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `3e803f7` moves periodic FSP rekey tick planning and due cutover/drain
  mutation behind `SessionRegistry`. The new guards
  `session_registry_owns_rekey_tick_selection` and
  `session_registry_owns_rekey_tick_cutover_and_drain_mutation` pin cutover
  delay, drain-window selection, dampening, msg3-in-flight suppression,
  jittered timer trigger, send-counter trigger, defensive cutover mutation,
  defensive drain completion, and the preserved behavior where an expired drain
  may also be selected for fresh rekey initiation in the same tick. Focused
  checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core rekey -- --nocapture`,
  `cargo test -p fips-core node::tests::session -- --nocapture`,
  `cargo test -p fips-core timeout -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1516` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing, crypto, sender,
  batching, or delivery semantics changed; the latest full Docker checkpoint
  remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `cdefb80` moves direct FSP rekey initiation eligibility and successful
  post-send state installation behind `SessionRegistry`. The new guards
  `session_registry_owns_session_rekey_initiation_eligibility` and
  `session_registry_owns_session_rekey_initiation_state_install` pin
  established-session eligibility, missing-session handling, in-progress and
  pending-new-session suppression, remote-public-key handoff, rekey handshake
  install, initiator flag, resend payload/timer, and decrypt-failure reset.
  Route availability remains a `Node`/route-owner concern before initiation.
  Focused checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core rekey -- --nocapture`,
  `cargo test -p fips-core node::tests::session -- --nocapture`,
  `cargo test -p fips-core timeout -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1518` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing, crypto, sender,
  batching, or delivery semantics changed; the latest full Docker checkpoint
  remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `373c867` moves periodic FMP rekey tick planning and due cutover/drain
  mutation behind `PeerLifecycleRegistry`. The new guards
  `peer_lifecycle_registry_owns_fmp_rekey_tick_selection` and
  `peer_lifecycle_registry_owns_fmp_rekey_tick_cutover_and_drain_mutation` pin
  active-peer healthy/session gating, responder-pending cutover suppression,
  drain-window selection, dampening, jittered age trigger, send-counter
  trigger, defensive cutover mutation, and defensive drain completion. `Node`
  still owns the external side effects after registry mutation: current-session
  worker registration, old session-index deregistration, index free, and
  logging. Focused checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core fmp_rekey -- --nocapture`,
  `cargo test -p fips-core rekey -- --nocapture`,
  `cargo test -p fips-core node::tests::session -- --nocapture`,
  `cargo test -p fips-core timeout -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1520` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing, crypto, sender,
  batching, or delivery semantics changed; the latest full Docker checkpoint
  remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `4ac092a` moves FMP rekey msg1 due-resend selection, exhausted-budget
  selection, abandon mutation, and successful resend accounting behind
  `PeerLifecycleRegistry`. The new guards
  `peer_lifecycle_registry_owns_fmp_rekey_msg1_resend_selection_and_accounting`
  and `peer_lifecycle_registry_owns_exhausted_fmp_rekey_msg1_cleanup` pin the
  transport/address/msg1 retry snapshot, resend backoff accounting, exhausted
  peer cleanup facts, and missing-target behavior. `Node` still owns the
  external side effects: transport send, pending-outbound removal,
  session-index deregistration, index free, and logging. Focused checks passed:
  `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core fmp_rekey -- --nocapture`,
  `cargo test -p fips-core rekey -- --nocapture`,
  `cargo test -p fips-core node::tests::session -- --nocapture`,
  `cargo test -p fips-core timeout -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1522` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing, crypto, sender,
  batching, or delivery semantics changed; the latest full Docker checkpoint
  remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `46e2c8e` moves FMP rekey initiation target selection and successful
  post-send state installation behind `PeerLifecycleRegistry`. The new guards
  `peer_lifecycle_registry_owns_fmp_rekey_initiation_target_snapshot` and
  `peer_lifecycle_registry_owns_fmp_rekey_initiation_state_install` pin the
  transport/address/link/pubkey initiation snapshot, missing-peer and missing
  transport behavior, in-progress handshake install, rekey index, msg1 payload,
  resend timer, and resend count reset. `Node` still owns index allocation/free,
  Noise msg1 construction, transport send, pending-outbound registration, and
  logging. Focused checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core fmp_rekey -- --nocapture`,
  `cargo test -p fips-core rekey -- --nocapture`,
  `cargo test -p fips-core node::tests::session -- --nocapture`,
  `cargo test -p fips-core timeout -- --nocapture`,
  `cargo test -p fips-core decrypt_failure -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo test -p fips-core decrypt_worker -- --nocapture`,
  `cargo test -p fips-core endpoint_event_runtime -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1524` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing, crypto, sender,
  batching, or delivery semantics changed; the latest full Docker checkpoint
  remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `0661713` moves link-layer MMP ReceiverReport peer-state processing
  behind `PeerLifecycleRegistry`. The new guards
  `peer_lifecycle_registry_owns_mmp_receiver_report_processing` and
  `peer_lifecycle_registry_owns_mmp_receiver_report_skip_paths` pin active-peer
  lookup, MMP-enabled gating, session timestamp lookup, metrics processing,
  SRTT report-interval feedback, reverse-delivery update, and unknown/non-MMP
  skip behavior. `Node` still owns wire decode, malformed/unknown logging,
  processed trace logging, and first-RTT parent/tree side effects. Focused
  checks passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core mmp -- --nocapture`,
  `cargo test -p fips-core routing -- --nocapture`,
  `cargo test -p fips-core spanning_tree -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1526` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing algorithm,
  crypto, sender, batching, or delivery semantics changed; the latest full
  Docker checkpoint remains nvpn `941cefd1` plus FIPS `5721357`.
- FIPS `4f59bde` moves periodic link-layer MMP report collection and metric-log
  cadence behind `PeerLifecycleRegistry`. The new guards
  `peer_lifecycle_registry_owns_due_mmp_link_report_collection` and
  `peer_lifecycle_registry_mmp_link_report_collection_respects_modes` pin
  active-peer iteration, MMP-enabled filtering, Full/Lightweight/Minimal mode
  gating, SenderReport and ReceiverReport due checks, report building/interval
  reset, metric snapshot creation, and log cadence mutation. `Node` still owns
  peer display-name rendering plus encrypted link-message sends. Focused checks
  passed: `cargo fmt --check`, `git diff --check`,
  `cargo test -p fips-core mmp -- --nocapture`,
  `cargo test -p fips-core routing -- --nocapture`,
  `cargo test -p fips-core spanning_tree -- --nocapture`,
  `cargo test -p fips-core forwarding -- --nocapture`,
  `cargo test -p fips-core peer_runtime_receive -- --nocapture`,
  `cargo check -p fips-core --release`, and full
  `cargo test -p fips-core -- --nocapture` (`1528` passed, `2` ignored;
  doctests `2` ignored). The nvpn local-FIPS hotpath also passed all six
  checks:
  `NVPN_FIPS_REPO_PATH=<fips-safety-worktree> ./scripts/test-dataplane-safety-fast.sh nvpn-hotpath`.
  No Docker perf rerun was taken because no queueing, routing algorithm,
  crypto, encrypted transport send, batching, or delivery semantics changed;
  the latest full Docker checkpoint remains nvpn `941cefd1` plus FIPS
  `5721357`.

Current local-to-Linux/VM host-pair status:

- A short direct-path smoke is recorded in the same baseline doc.
- A finalized-script rerun reproduced a tunnel loss failure before the second
  sample completed; treat this as safety-net evidence, not as a completed
  30-60 minute soak.
- A later `1800` second host/VM soak attempt failed on sample `1` when
  remote-to-local tunnel ping loss reached `10%` against the default `5%`
  ceiling; that failure is recorded in the baseline doc.
- A later strict direct-path `1800` second host/VM soak completed with `13`
  samples, direct-path checks active in every row, no route/SRTT/counter/CPU
  wedge, and late tolerated TCP-burst degradation. Treat it as completed
  host/VM safety evidence, not a clean throughput baseline.

## Architecture Direction

After this safety net is green, refactor in small reversible steps. The concrete
plan is `docs/fips-dataplane-architecture-plan.md`; the short version is:

- Prefer a per-peer or per-shard owner for UDP drain, decrypt/open,
  session/replay, encrypt/seal, and send batching.
- Use wireguard-go, Tailscale, and BoringTun as references for a boring,
  isolated dataplane, not as code to port wholesale. Latest local reference
  recheck for the architecture plan used wireguard-go `f333402`, BoringTun
  `cdf3b24`, and Tailscale `7a43e41a2`.
- Keep the rx loop as a coordinator, not a crypto+send bottleneck.
- Preserve a reserved priority lane plus bounded bulk lane.
- Keep Linux GSO/sendmmsg where supported.
- Keep macOS sender changes conservative until real Mac Wi-Fi/screenshare soak
  proves the replacement stable.
- Keep connected UDP if soak-stable; add a large-mesh escape hatch or shard
  drain before one-thread-per-peer becomes a scaling problem.

## Validation Boundary

This branch can validate Linux/docker and local-to-Linux/VM style paths. It must
not be used to claim real Mac-to-Mac coverage. The operator-local follow-up is a
real Mac Wi-Fi/screenshare soak with the same metrics: tunnel ping both ways,
short iperf bursts, FIPS peer status, queue/drop counters, and daemon CPU over
30-60 minutes.
