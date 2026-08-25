#!/usr/bin/env bash
# Selectable local checks for dataplane safety/benchmark iteration.
#
# These suites intentionally avoid live Docker, SSH, sudo, and TUN setup unless
# a named cargo test itself requires the local machine to build project code.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOCK_SNAPSHOT=""

fail() {
  printf 'dataplane safety fast test failed: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: scripts/test-dataplane-safety-fast.sh [suite ...]

Suites:
  harnesses           Shell syntax plus local harness self-tests.
  comparison-dry-run  Dry-run the clean/stress BoringTun + wireguard-go matrix.
  core                Focused nostr-vpn-core route/admission tests.
  nvpn-hotpath        Focused nvpn/FIPS dataplane queue, TUN, and endpoint-data tests.
  nvpn-reliability    Focused nvpn liveness, transit etiquette, and roster-gate tests.
  macos-route         Focused macOS captive-portal/underlay route policy tests.
  nvpn                Aggregate nvpn-hotpath, nvpn-reliability, and macos-route.
  app-state           Focused app-core daemon status JSON compatibility test.
  fips                Focused local-FIPS reliability/observability tests.
  all                 Run local nvpn suites; includes fips when NVPN_FIPS_REPO_PATH is set.
  list                Print suite names.

Default:
  harnesses comparison-dry-run

Set NVPN_FIPS_REPO_PATH=/path/to/fips when running nvpn/app-state against
unreleased local FIPS crates, or when running the fips suite. Cargo.lock is
restored after local-FIPS nvpn cargo runs so benchmark/safety iteration does
not leave lockfile churn behind.
EOF
}

list_suites() {
  printf '%s\n' \
    harnesses \
    comparison-dry-run \
    core \
    nvpn-hotpath \
    nvpn-reliability \
    macos-route \
    nvpn \
    app-state \
    fips \
    all
}

run() {
  printf '== %s ==\n' "$*"
  "$@"
}

restore_lock() {
  if [[ -n "$LOCK_SNAPSHOT" && -f "$LOCK_SNAPSHOT" && -f "$ROOT_DIR/Cargo.lock" ]]; then
    if ! cmp -s "$LOCK_SNAPSHOT" "$ROOT_DIR/Cargo.lock"; then
      cp -p "$LOCK_SNAPSHOT" "$ROOT_DIR/Cargo.lock"
      printf 'restored Cargo.lock after local-FIPS cargo run\n'
    fi
  fi
}

prepare_lock_restore() {
  [[ -z "$LOCK_SNAPSHOT" ]] || return 0
  LOCK_SNAPSHOT="$(mktemp)"
  cp -p "$ROOT_DIR/Cargo.lock" "$LOCK_SNAPSHOT"
  trap restore_lock EXIT
}

cargo_config_args=()

run_cargo_test_checked() {
  local output status
  output="$(mktemp)"
  set +e
  "$@" >"$output" 2>&1
  status=$?
  set -e
  cat "$output"
  if ((status != 0)); then
    rm -f "$output"
    return "$status"
  fi
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed;' "$output"; then
    rm -f "$output"
    fail "focused cargo test selected zero tests: $*"
  fi
  rm -f "$output"
}

prepare_cargo_config() {
  cargo_config_args=()
  if [[ -n "${NVPN_FIPS_REPO_PATH:-}" ]]; then
    local fips_path
    fips_path="$(validated_fips_repo_path)"
    prepare_lock_restore
    cargo_config_args+=(
      --config "patch.crates-io.nvpn-fips-core.path=\"$fips_path/crates/fips-core\""
      --config "patch.crates-io.nvpn-fips-endpoint.path=\"$fips_path/crates/fips-endpoint\""
      --config "patch.crates-io.nvpn-fips-identity.path=\"$fips_path/crates/fips-identity\""
    )
    printf 'using local FIPS crates from %s\n' "$fips_path"
  fi
}

cargo_test() {
  prepare_cargo_config
  if ((${#cargo_config_args[@]})); then
    (cd "$ROOT_DIR" && run_cargo_test_checked cargo test "${cargo_config_args[@]}" "$@")
  else
    (cd "$ROOT_DIR" && run_cargo_test_checked cargo test "$@")
  fi
}

validated_fips_repo_path() {
  local fips_path="${NVPN_FIPS_REPO_PATH:-}"
  [[ -n "$fips_path" ]] || fail "suite 'fips' requires NVPN_FIPS_REPO_PATH=/path/to/fips"
  [[ -d "$fips_path/crates/fips-core" ]] || fail "missing $fips_path/crates/fips-core"
  [[ -d "$fips_path/crates/fips-endpoint" ]] || fail "missing $fips_path/crates/fips-endpoint"
  [[ -d "$fips_path/crates/fips-identity" ]] || fail "missing $fips_path/crates/fips-identity"
  printf '%s\n' "$fips_path"
}

fips_cargo_test() {
  local fips_path
  fips_path="$(validated_fips_repo_path)"
  (cd "$fips_path" && run_cargo_test_checked cargo test "$@")
}

run_harnesses() {
  local scripts=(
    scripts/bench-userspace-wg-host-pair.sh
    scripts/build-e2e-docker-base-images.sh
    scripts/compare-docker-benchmarks.sh
    scripts/compare-host-pair-benchmarks.sh
    scripts/install-nvpn-test-daemon
    scripts/lib-docker-bench-summary.sh
    scripts/perf-docker.sh
    scripts/perf-docker-relay.sh
    scripts/perf-docker-boringtun.sh
    scripts/perf-docker-wireguard-go.sh
    scripts/release-gate-host-pair-latency.sh
    scripts/release-gate-host-pair-loaded-latency.sh
    scripts/run-darwin-docker-wg-reference.sh
    scripts/run-host-pair-comparison.sh
    scripts/soak-fips-dataplane-docker.sh
    scripts/soak-fips-dataplane-host-pair.sh
    scripts/summarize-fips-soak-docker.sh
    scripts/summarize-host-pair-comparison-run.sh
    scripts/test-docker-reference-harness.sh
    scripts/test-e2e-docker-base-images-harness.sh
    scripts/test-fips-perf-harness.sh
    scripts/test-fips-platform-matrix-harness.sh
    scripts/test-fips-soak-harness.sh
    scripts/test-fips-soak-summary.sh
    scripts/test-darwin-docker-wg-reference-runner.sh
    scripts/test-host-pair-comparison-harness.sh
    scripts/test-host-pair-comparison-runner.sh
    scripts/test-host-pair-harness.sh
    scripts/test-idle-cpu-gate-harness.sh
    scripts/test-install-nvpn-test-daemon.sh
    scripts/test-mobile-platform-tools.sh
    scripts/test-release-gate-timeout-harness.sh
    scripts/test-userspace-wg-host-pair-harness.sh
  )
  run bash -n "${scripts[@]/#/$ROOT_DIR/}"
  run "$ROOT_DIR/scripts/test-fips-perf-harness.sh"
  run "$ROOT_DIR/scripts/test-e2e-docker-base-images-harness.sh"
  run "$ROOT_DIR/scripts/test-fips-platform-matrix-harness.sh"
  run "$ROOT_DIR/scripts/test-fips-soak-harness.sh"
  run "$ROOT_DIR/scripts/test-fips-soak-summary.sh"
  run "$ROOT_DIR/scripts/test-darwin-docker-wg-reference-runner.sh"
  run "$ROOT_DIR/scripts/test-docker-reference-harness.sh"
  run "$ROOT_DIR/scripts/test-host-pair-harness.sh"
  run "$ROOT_DIR/scripts/test-host-pair-comparison-harness.sh"
  run "$ROOT_DIR/scripts/test-host-pair-comparison-runner.sh"
  run "$ROOT_DIR/scripts/test-idle-cpu-gate-harness.sh"
  run "$ROOT_DIR/scripts/test-mobile-platform-tools.sh"
  run "$ROOT_DIR/scripts/test-release-gate-timeout-harness.sh"
  run "$ROOT_DIR/scripts/test-install-nvpn-test-daemon.sh"
  run "$ROOT_DIR/scripts/test-userspace-wg-host-pair-harness.sh"
  run_loaded_latency_dry_run
}

run_comparison_dry_run() {
  local dir out
  dir="$(mktemp -d)"
  out="$dir/dry-run.log"
  NVPN_HOST_PAIR_COMPARISON_DRY_RUN=1 \
    NVPN_HOST_PAIR_COMPARISON_RUN_OUTPUT_DIR="$dir/bundle" \
    NVPN_HOST_PAIR_COMPARISON_SSH=bench-host \
    NVPN_HOST_PAIR_COMPARISON_LOCAL_UNDERLAY_IP=192.0.2.10 \
    NVPN_HOST_PAIR_COMPARISON_REMOTE_UNDERLAY_IP=192.0.2.20 \
    NVPN_HOST_PAIR_COMPARISON_BACKENDS=boringtun,wireguard-go \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_MODES=clean,stress \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_SIDES=both \
    NVPN_HOST_PAIR_COMPARISON_CPU_STRESS_WORKERS=auto \
    NVPN_HOST_PAIR_COMPARISON_DURATION_SECS=120 \
    NVPN_HOST_PAIR_COMPARISON_INTERVAL_SECS=30 \
    NVPN_HOST_PAIR_COMPARISON_PING_COUNT=10 \
    NVPN_HOST_PAIR_COMPARISON_IPERF_DURATION_SECS=3 \
    "$ROOT_DIR/scripts/run-host-pair-comparison.sh" >"$out"

  grep -Fq '== nvpn/FIPS host-pair row (clean) ==' "$out" \
    || fail "comparison dry-run did not include clean nvpn row"
  grep -Fq '== nvpn/FIPS host-pair row (stress) ==' "$out" \
    || fail "comparison dry-run did not include stress nvpn row"
  grep -Fq 'NVPN_WG_HOST_PAIR_BACKEND=boringtun' "$out" \
    || fail "comparison dry-run did not include BoringTun row"
  grep -Fq 'NVPN_WG_HOST_PAIR_BACKEND=wireguard-go' "$out" \
    || fail "comparison dry-run did not include wireguard-go row"
  [[ ! -e "$dir/bundle" ]] || fail "comparison dry-run created an output bundle"
  rm -rf "$dir"
  printf 'comparison dry-run matrix mapping passed\n'
}

run_loaded_latency_dry_run() {
  local dir out
  dir="$(mktemp -d)"
  out="$dir/loaded-latency-dry-run.log"
  NVPN_RELEASE_GATE_HOST_PAIR_LOADED_LATENCY=1 \
    NVPN_RELEASE_GATE_HOST_PAIR_LOADED_LATENCY_DRY_RUN=1 \
    NVPN_RELEASE_GATE_HOST_PAIR_LOADED_LATENCY_SSH=bench-host \
    NVPN_RELEASE_GATE_HOST_PAIR_LOADED_DURATION_SECS=120 \
    NVPN_RELEASE_GATE_HOST_PAIR_LOADED_SAMPLE_INTERVAL_SECS=30 \
    NVPN_RELEASE_GATE_HOST_PAIR_LOADED_IPERF_DURATION_SECS=3 \
    "$ROOT_DIR/scripts/release-gate-host-pair-loaded-latency.sh" >"$out"

  grep -Fq 'NVPN_RELEASE_GATE_HOST_PAIR_LOADED_DURATION_SECS=120' "$out" \
    || fail "loaded latency dry-run did not include duration"
  grep -Fq 'NVPN_RELEASE_GATE_HOST_PAIR_LOADED_SAMPLE_INTERVAL_SECS=30' "$out" \
    || fail "loaded latency dry-run did not include sample interval"
  grep -Fq 'NVPN_RELEASE_GATE_HOST_PAIR_LOADED_MAX_P99_MS=1000' "$out" \
    || fail "loaded latency dry-run did not include default p99 threshold"
  grep -Fq 'NVPN_RELEASE_GATE_HOST_PAIR_LOADED_MAX_SUB_1MBPS_INTERVALS=0' "$out" \
    || fail "loaded latency dry-run did not include default sub-1 Mbps threshold"
  grep -Fq 'NVPN_RELEASE_GATE_HOST_PAIR_LOADED_MAX_STALL_INTERVALS=1' "$out" \
    || fail "loaded latency dry-run did not include default stall threshold"
  grep -Fq 'release-gate-host-pair-loaded-latency.sh' "$out" \
    || fail "loaded latency dry-run did not include script path"
  rm -rf "$dir"
  printf 'loaded latency dry-run mapping passed\n'
}

run_core() {
  run cargo_test -p nostr-vpn-core two_device_private_mesh_routes_and_admits_bidirectional_packets
  run cargo_test -p nostr-vpn-core equal_prefix_route_ambiguity_is_dropped
  run cargo_test -p nostr-vpn-core fallback_prefix_index_skips_exact_routes_and_preserves_longest_prefix
}

run_nvpn_hotpath() {
  run cargo_test -p nvpn raw_tun_write_keeps_fd_open_and_writes_platform_frame
  run cargo_test -p nvpn blocking_tun_write_keeps_fd_open_and_writes_platform_frame
  run cargo_test -p nvpn tun_pipeline_packet_caches_destination_for_send_route
  run cargo_test -p nvpn local_tun_pipeline_packets_are_detected_before_mesh_send
  run cargo_test -p nvpn drain_event_batch_respects_limit
  run cargo_test -p nvpn percentile_uses_observed_histogram_count_when_stage_count_leads
  run cargo_test -p nvpn peer_activity_map_preserves_existing_configured_peer_activity
  run cargo_test -p nvpn peer_identity_map_resolves_endpoint_identities_and_skips_invalid_npubs
  run cargo_test -p nvpn control_frame_destinations_can_target_pending_join_requester
  run cargo_test -p nvpn endpoint_data_runtime_sends_and_receives_raw_packet_batch
  run cargo_test -p nvpn endpoint_data_runtime_sends_tun_pipeline_batch_without_repacking
  run cargo_test -p nvpn endpoint_data_runtime_recv_batch_into_reuses_buffers
}

run_nvpn_reliability() {
  run cargo_test -p nvpn fips_peer_liveness_rejects_far_future_presence
  run cargo_test -p nvpn fips_peer_ping_due_recovers_from_future_timestamps
  run cargo_test -p nvpn endpoint_config_keeps_static_transit_peers_outside_mesh_routes
  run cargo_test -p nvpn endpoint_config_keeps_default_route_roster_peers_as_transit
  run cargo_test -p nvpn tunnel_config_seeds_recent_transit_without_granting_routes
  run cargo_test -p nvpn tunnel_config_caps_recent_non_roster_transit_peers
  run cargo_test -p nvpn open_discovery_does_not_loosen_tun_roster_gate
}

run_macos_route() {
  run cargo_test -p nvpn captive_portal -- --nocapture
  run cargo_test -p nvpn macos_default_routes_from_netstat_finds_underlay_and_utun_routes
  run cargo_test -p nvpn macos_route_parser_keeps_private_routes_via_local_underlay_gateway
  run cargo_test -p nvpn macos_route_get_rejects_private_endpoint_via_hotspot_default_gateway
  run cargo_test -p nvpn macos_route_get_keeps_private_endpoint_on_direct_lan
  run cargo_test -p nvpn macos_route_monitor_observes_route_and_interface_changes
}

run_nvpn() {
  run_nvpn_hotpath
  run_nvpn_reliability
  run_macos_route
}

run_app_state() {
  run cargo_test -p nostr-vpn-app-core daemon_runtime_state_accepts_cli_snake_case_json
  run cargo_test -p nostr-vpn-app-core mobile_peer_identity_map_resolves_endpoint_identities_and_skips_invalid_npubs
  run cargo_test -p nostr-vpn-app-core mobile_endpoint_send_run_batches_consecutive_resolved_peer
}

run_fips() {
  run fips_cargo_test -p nvpn-fips-core overlay_adverts -- --nocapture
  run fips_cargo_test -p nvpn-fips-core update_peers -- --nocapture
  run fips_cargo_test -p nvpn-fips-core non_reconnect -- --nocapture
  run fips_cargo_test -p nvpn-fips-core active_fallback -- --nocapture
  run fips_cargo_test -p nvpn-fips-core live_node_owner_routes_send_endpoint_and_tun_to_transport -- --nocapture
  run fips_cargo_test -p nvpn-fips-core live_route_table_outbound_source_preserves_tun_slice_after_endpoint_batch_overrun -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_runtime_owns_attach_delivery_and_backlog -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_queue_owns_backlog_message_count -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_queue_preserves_fifo_for_mixed_payload_sizes -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_queue_drops_app_data_when_full -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_queue_dropped_batch_counts_as_success -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_queue_partially_admits_batch_at_message_boundary -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_capacity_counts_messages_not_batches -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_message_count_treats_batch_items_as_public_messages -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_queue_send_fails_after_receiver_drop -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_queue_closes_after_all_senders_drop -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_event_queue_async_recv_closes_when_senders_drop -- --nocapture
  run fips_cargo_test -p nvpn-fips-core recv_batch_drains_ready_loopback_endpoint_data -- --nocapture
  run fips_cargo_test -p nvpn-fips-core recv_batch_into_splits_internal_endpoint_batches_without_reordering -- --nocapture
  run fips_cargo_test -p nvpn-fips-core recv_batch_into_preserves_pending_batch_tail_fifo -- --nocapture
  run fips_cargo_test -p nvpn-fips-core endpoint_data_batch_enqueue_drops_when_full -- --nocapture
  run fips_cargo_test -p nvpn-fips-core packet_channel_batch_send_amortizes_bulk_channel_items -- --nocapture
  run fips_cargo_test -p nvpn-fips-core packet_channel_reuses_pooled_batch_container_after_rx_drain -- --nocapture
  run fips_cargo_test -p nvpn-fips-core packet_channel_recycles_pooled_packet_buffer_when_bulk_batch_is_dropped -- --nocapture
  run fips_cargo_test -p nvpn-fips-core packet_channel_keeps_single_lane_batches_grouped -- --nocapture
  run fips_cargo_test -p nvpn-fips-core packet_channel_dequeue_counts_preserve_item_and_lane_counts -- --nocapture
  run fips_cargo_test -p nvpn-fips-core packet_channel_priority_overtakes_pending_bulk_batch_tail -- --nocapture
}

run_suite() {
  case "$1" in
    harnesses) run_harnesses ;;
    comparison-dry-run) run_comparison_dry_run ;;
    core) run_core ;;
    nvpn-hotpath) run_nvpn_hotpath ;;
    nvpn-reliability) run_nvpn_reliability ;;
    macos-route) run_macos_route ;;
    nvpn) run_nvpn ;;
    app-state) run_app_state ;;
    fips) run_fips ;;
    all)
      run_harnesses
      run_comparison_dry_run
      run_core
      run_nvpn
      run_app_state
      if [[ -n "${NVPN_FIPS_REPO_PATH:-}" ]]; then
        run_fips
      else
        printf 'skipping fips suite because NVPN_FIPS_REPO_PATH is not set\n'
      fi
      ;;
    list) list_suites ;;
    -h|--help|help) usage ;;
    *) fail "unknown suite '$1'; run with 'list' to see options" ;;
  esac
}

main() {
  if (($# == 0)); then
    set -- harnesses comparison-dry-run
  fi
  local suite
  for suite in "$@"; do
    run_suite "$suite"
  done
}

main "$@"
