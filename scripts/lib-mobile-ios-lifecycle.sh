#!/usr/bin/env bash

ios_lifecycle_copy_result() {
  local device="$1"
  local bundle_id="$2"
  local result_name="$3"
  local destination="$4"
  rm -f "$destination"
  xcrun devicectl device copy from \
    --device "$device" \
    --domain-type appDataContainer \
    --domain-identifier "$bundle_id" \
    --source "Library/Application Support/Nostr VPN Debug Results/$result_name" \
    --destination "$destination" \
    --quiet
}

ios_lifecycle_validate_history() {
  local history="$1"
  local markers="$2"
  local run_id="$3"
  local cycles="$4"
  local dwell_seconds="$5"

  python3 - "$history" "$markers" "$run_id" "$cycles" "$dwell_seconds" <<'PY'
import json
import sys

history_path, marker_path, run_id, cycles_raw, dwell_raw = sys.argv[1:]
cycles = int(cycles_raw)
dwell_milliseconds = int(dwell_raw) * 1_000

with open(history_path, encoding="utf-8") as handle:
    receipt = json.load(handle)
with open(marker_path, encoding="utf-8") as handle:
    marker_lines = [line.strip() for line in handle if line.strip()]

if receipt.get("runId") != run_id:
    raise SystemExit("lifecycle receipt run ID does not match this device run")
history = receipt.get("history")
if not isinstance(history, list) or not history:
    raise SystemExit("lifecycle receipt has no transition history")
if history[0].get("phase") != "armed":
    raise SystemExit("lifecycle history does not start with its armed event")

transitions = [event.get("transition") for event in history]
if transitions != list(range(1, len(history) + 1)):
    raise SystemExit(f"lifecycle transitions are not contiguous: {transitions!r}")

processes = {event.get("processIdentifier") for event in history}
if len(processes) != 1 or None in processes:
    raise SystemExit(f"lifecycle gate crossed app processes: {processes!r}")

previous_wall = 0
previous_monotonic = 0
background = None
pairs = []
for event in history:
    wall = event.get("wallClockMilliseconds")
    monotonic = event.get("monotonicMilliseconds")
    if not isinstance(wall, int) or wall < previous_wall:
        raise SystemExit("lifecycle wall-clock history is missing or unordered")
    if not isinstance(monotonic, int) or monotonic < previous_monotonic:
        raise SystemExit("lifecycle monotonic history is missing or unordered")
    previous_wall = wall
    previous_monotonic = monotonic

    phase = event.get("phase")
    core_available = event.get("nativeCoreAvailable")
    if phase == "background":
        if core_available is not False:
            raise SystemExit("native core remained available in a background event")
        if background is not None:
            raise SystemExit("two background events occurred without an active event")
        background = event
    elif phase == "active" and background is not None:
        if core_available is not True:
            raise SystemExit("native core was unavailable in an active event")
        elapsed = monotonic - background["monotonicMilliseconds"]
        if elapsed < dwell_milliseconds - 250:
            raise SystemExit(
                f"background dwell was only {elapsed}ms; expected about {dwell_milliseconds}ms"
            )
        pairs.append((background, event))
        background = None

if background is not None:
    raise SystemExit("lifecycle history ended while the app was backgrounded")
if len(pairs) != cycles:
    raise SystemExit(f"lifecycle history has {len(pairs)} completed cycles; expected {cycles}")
if receipt.get("phase") != "active" or receipt.get("nativeCoreAvailable") is not True:
    raise SystemExit("final lifecycle receipt is not active with a reopened native core")
if receipt.get("transition") != history[-1].get("transition"):
    raise SystemExit("final lifecycle transition does not match the retained history")

required_markers = {
    f"NVPN_IOS_LIFECYCLE_RUN_ID={run_id}",
    f"NVPN_IOS_LIFECYCLE_RESULT_NAME={history_path.rsplit('/', 1)[-1].replace('-history', '')}",
}
if not required_markers.issubset(set(marker_lines)):
    raise SystemExit("device lifecycle marker receipt is stale or incomplete")

def marker_milliseconds(name):
    prefix = f"{name}="
    values = [line[len(prefix):] for line in marker_lines if line.startswith(prefix)]
    if len(values) != 1:
        raise SystemExit(f"expected one {name} marker, got {len(values)}")
    try:
        return int(values[0])
    except ValueError as error:
        raise SystemExit(f"{name} is not a timestamp") from error

passed = marker_milliseconds("NVPN_IOS_LIFECYCLE_DRIVER_PASSED_MS")
previous = marker_milliseconds("NVPN_IOS_LIFECYCLE_LAUNCH_FOREGROUND_MS")
for cycle in range(1, cycles + 1):
    background_requested = marker_milliseconds(
        f"NVPN_IOS_LIFECYCLE_CYCLE_{cycle}_BACKGROUND_REQUESTED_MS"
    )
    observed = marker_milliseconds(
        f"NVPN_IOS_LIFECYCLE_CYCLE_{cycle}_BACKGROUND_OBSERVED_MS"
    )
    activate = marker_milliseconds(
        f"NVPN_IOS_LIFECYCLE_CYCLE_{cycle}_ACTIVATE_REQUESTED_MS"
    )
    foreground = marker_milliseconds(
        f"NVPN_IOS_LIFECYCLE_CYCLE_{cycle}_FOREGROUND_OBSERVED_MS"
    )
    if not previous <= background_requested <= observed <= activate <= foreground <= passed:
        raise SystemExit(f"device cycle {cycle} timestamps are unordered")
    if activate - observed < dwell_milliseconds - 250:
        raise SystemExit(
            f"device cycle {cycle} dwell was {activate - observed}ms; "
            f"expected about {dwell_milliseconds}ms"
        )
    previous = foreground

print(
    json.dumps(
        {
            "cycles": cycles,
            "dwellMilliseconds": dwell_milliseconds,
            "firstBackgroundWallClockMilliseconds": pairs[0][0]["wallClockMilliseconds"],
            "lastForegroundWallClockMilliseconds": pairs[-1][1]["wallClockMilliseconds"],
            "processIdentifier": next(iter(processes)),
            "runId": run_id,
            "transitions": len(history),
        },
        sort_keys=True,
    )
)
PY
}

ios_lifecycle_milliseconds() {
  python3 - <<'PY'
import time
print(int(time.time() * 1_000))
PY
}

ios_lifecycle_mark() {
  local marker_file="$1"
  local name="$2"
  printf '%s=%s\n' "$name" "$(ios_lifecycle_milliseconds)" >>"$marker_file"
}

ios_lifecycle_activate() {
  local device="$1"
  local bundle_id="$2"
  xcrun devicectl device process launch \
    --device "$device" \
    --activate \
    --quiet \
    "$bundle_id"
}

ios_lifecycle_launch_fresh() {
  local device="$1"
  local bundle_id="$2"
  shift 2
  xcrun devicectl device process launch \
    --device "$device" \
    --activate \
    --quiet \
    "$bundle_id" "$@"
}

ios_lifecycle_receipt_has_transition() {
  local receipt="$1"
  local phase="$2"
  local transition="$3"
  python3 - "$receipt" "$phase" "$transition" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
phase = sys.argv[2]
transition = int(sys.argv[3])
expected_core = phase != "background"
raise SystemExit(
    0 if result.get("phase") == phase
    and result.get("transition") == transition
    and result.get("nativeCoreAvailable") is expected_core
    else 1
)
PY
}

ios_lifecycle_wait_for_transition() {
  local device="$1"
  local bundle_id="$2"
  local result_name="$3"
  local destination="$4"
  local phase="$5"
  local transition="$6"
  local timeout_seconds="${NVPN_IOS_LIFECYCLE_TRANSITION_TIMEOUT_SECS:-45}"
  local deadline="$((SECONDS + timeout_seconds))"
  while (( SECONDS < deadline )); do
    if ios_lifecycle_copy_result \
      "$device" "$bundle_id" "$result_name" "$destination" 2>/dev/null \
      && ios_lifecycle_receipt_has_transition "$destination" "$phase" "$transition"
    then
      return 0
    fi
    sleep 0.25
  done
  echo "iOS lifecycle timed out awaiting $phase transition $transition" >&2
  return 1
}

ios_lifecycle_wait_for_active_tunnel_cycle() {
  local device="$1"
  local bundle_id="$2"
  local result_name="$3"
  local destination="$4"
  local cycle="$5"
  local timeout_seconds="${NVPN_IOS_LIFECYCLE_PROBE_TIMEOUT_SECS:-60}"
  local deadline="$((SECONDS + timeout_seconds))"
  while (( SECONDS < deadline )); do
    if ios_lifecycle_copy_result \
      "$device" "$bundle_id" "$result_name" "$destination" 2>/dev/null \
      && python3 - "$destination" "$cycle" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
cycle = int(sys.argv[2])
raise SystemExit(0 if result.get("activeTunnelLifecycleCycles", 0) >= cycle else 1)
PY
    then
      return 0
    fi
    sleep 0.25
  done
  echo "iOS lifecycle timed out re-proving the active tunnel after cycle $cycle" >&2
  return 1
}

ios_lifecycle_wait_for_active_tunnel_ready() {
  local device="$1"
  local bundle_id="$2"
  local result_name="$3"
  local destination="$4"
  local timeout_seconds="${NVPN_IOS_LIFECYCLE_PROBE_TIMEOUT_SECS:-60}"
  local deadline="$((SECONDS + timeout_seconds))"
  while (( SECONDS < deadline )); do
    if ios_lifecycle_copy_result \
      "$device" "$bundle_id" "$result_name" "$destination" 2>/dev/null \
      && python3 - "$destination" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
raise SystemExit(
    0 if result.get("phase") == "awaiting_active_tunnel_lifecycle_cycle_1"
    and result.get("packetTunnelConnected") is True
    and result.get("packetTunnelStatusRawValue") == 3
    else 1
)
PY
    then
      return 0
    fi
    sleep 0.25
  done
  echo "iOS lifecycle timed out awaiting the initial active tunnel" >&2
  return 1
}

ios_lifecycle_argument_value() {
  local requested="$1"
  shift
  while [[ "$#" -gt 1 ]]; do
    if [[ "$1" == "$requested" ]]; then
      printf '%s\n' "$2"
      return 0
    fi
    shift
  done
  return 1
}

_run_ios_app_lifecycle_gate() {
  local device="$1"
  local bundle_id="$2"
  local result_dir="$3"
  local cycles="$4"
  local mode="$5"
  shift 5
  local result_prefix run_id_prefix gate_description
  case "$mode" in
    standalone)
      result_prefix="mobile-ios-lifecycle"
      run_id_prefix="ios-lifecycle"
      gate_description="physical lifecycle"
      ;;
    active-tunnel)
      result_prefix="mobile-ios-active-tunnel-lifecycle"
      run_id_prefix="ios-active-tunnel-lifecycle"
      gate_description="active-tunnel lifecycle"
      ;;
    *)
      echo "Unknown iOS lifecycle gate mode: $mode" >&2
      return 1
      ;;
  esac

  local result_name="$result_prefix-$$-$RANDOM.json"
  local stem="${result_name%.json}"
  local background_dwell="${NVPN_IOS_LIFECYCLE_BACKGROUND_DWELL_SECS:-10}"
  local run_id="$run_id_prefix-$$-$RANDOM-$(date +%s)"
  local markers="$result_dir/$stem-markers.log"
  local history="$result_dir/$stem-history.json"
  local summary="$result_dir/$stem-summary.json"
  local probe_state="$result_dir/$stem-probe-state.json"
  local probe_result_name=""
  local lifecycle_timeout
  local -a app_arguments=("$@")

  if ! [[ "$cycles" =~ ^[1-5]$ ]]; then
    echo "iOS $gate_description gate requires 1-5 lifecycle cycles" >&2
    return 1
  fi
  if ! [[ "$background_dwell" =~ ^[0-9]+$ ]]; then
    echo "iOS $gate_description gate requires an integer background dwell" >&2
    return 1
  fi
  if [[ "$mode" == "active-tunnel" ]]; then
    if (( background_dwell < 10 )); then
      echo "iOS active-tunnel lifecycle requires at least 10s background dwell" >&2
      return 1
    fi
    probe_result_name="$(ios_lifecycle_argument_value --nvpn-debug-result "$@")" || {
      echo "iOS active-tunnel lifecycle requires a debug probe result name" >&2
      return 1
    }
    lifecycle_timeout="$((background_dwell * cycles + 40 * cycles + 30))"
    app_arguments+=(
      --nvpn-debug-lifecycle-result "$result_name"
      --nvpn-debug-lifecycle-run-id "$run_id"
      --nvpn-debug-await-active-tunnel-lifecycle
      --nvpn-debug-active-lifecycle-cycles "$cycles"
      --nvpn-debug-active-lifecycle-timeout-seconds "$lifecycle_timeout"
    )
  else
    app_arguments=(
      --nvpn-debug-lifecycle-result "$result_name"
      --nvpn-debug-lifecycle-run-id "$run_id"
    )
  fi

  mkdir -p "$result_dir"
  rm -f "$markers" "$history" "$summary" "$summary.error" "$probe_state"
  printf 'NVPN_IOS_LIFECYCLE_RUN_ID=%s\n' "$run_id" >"$markers"
  printf 'NVPN_IOS_LIFECYCLE_RESULT_NAME=%s\n' "$result_name" >>"$markers"

  disconnect_ios_vpn_confirmed "$device"
  terminate_ios_app_processes_before_install "$device"
  ios_lifecycle_mark "$markers" NVPN_IOS_LIFECYCLE_LAUNCH_REQUESTED_MS
  ios_lifecycle_launch_fresh "$device" "$bundle_id" "${app_arguments[@]}"
  ios_lifecycle_wait_for_transition \
    "$device" "$bundle_id" "$result_name" "$history" armed 1
  ios_lifecycle_mark "$markers" NVPN_IOS_LIFECYCLE_LAUNCH_FOREGROUND_MS
  if [[ "$mode" == "active-tunnel" ]]; then
    ios_lifecycle_wait_for_active_tunnel_ready \
      "$device" "$bundle_id" "$probe_result_name" "$probe_state"
  fi

  local cycle background_transition active_transition
  for cycle in $(seq 1 "$cycles"); do
    background_transition="$((cycle * 2))"
    active_transition="$((background_transition + 1))"
    ios_lifecycle_mark \
      "$markers" "NVPN_IOS_LIFECYCLE_CYCLE_${cycle}_BACKGROUND_REQUESTED_MS"
    ios_lifecycle_activate "$device" "com.apple.Preferences"
    ios_lifecycle_wait_for_transition \
      "$device" "$bundle_id" "$result_name" "$history" \
      background "$background_transition"
    ios_lifecycle_mark \
      "$markers" "NVPN_IOS_LIFECYCLE_CYCLE_${cycle}_BACKGROUND_OBSERVED_MS"

    sleep "$background_dwell"

    ios_lifecycle_mark \
      "$markers" "NVPN_IOS_LIFECYCLE_CYCLE_${cycle}_ACTIVATE_REQUESTED_MS"
    ios_lifecycle_activate "$device" "$bundle_id"
    ios_lifecycle_wait_for_transition \
      "$device" "$bundle_id" "$result_name" "$history" \
      active "$active_transition"
    ios_lifecycle_mark \
      "$markers" "NVPN_IOS_LIFECYCLE_CYCLE_${cycle}_FOREGROUND_OBSERVED_MS"
    if [[ "$mode" == "active-tunnel" ]]; then
      ios_lifecycle_wait_for_active_tunnel_cycle \
        "$device" "$bundle_id" "$probe_result_name" "$probe_state" "$cycle"
    fi
  done

  ios_lifecycle_mark "$markers" NVPN_IOS_LIFECYCLE_DRIVER_PASSED_MS
  ios_lifecycle_copy_result "$device" "$bundle_id" "$result_name" "$history"
  if ios_lifecycle_validate_history \
    "$history" "$markers" "$run_id" "$cycles" "$background_dwell" \
    >"$summary" 2>"$summary.error"
  then
    rm -f "$summary.error" "$probe_state"
    printf 'iOS %s gate passed: %s cycles, %ss dwell; artifacts: %s\n' \
      "$gate_description" "$cycles" "$background_dwell" "$result_dir"
    return 0
  fi

  cat "$summary.error" >&2 2>/dev/null || true
  echo "iOS $gate_description app-side lifecycle history was incomplete." >&2
  echo "iOS $gate_description artifacts: $result_dir" >&2
  return 1
}

run_ios_app_lifecycle_gate() {
  local device="$1"
  local bundle_id="$2"
  local result_dir="$3"
  local cycles="$4"
  _run_ios_app_lifecycle_gate \
    "$device" "$bundle_id" "$result_dir" "$cycles" standalone
}

run_ios_active_tunnel_lifecycle_gate() {
  local device="$1"
  local bundle_id="$2"
  local result_dir="$3"
  local cycles="$4"
  shift 4
  _run_ios_app_lifecycle_gate \
    "$device" "$bundle_id" "$result_dir" "$cycles" active-tunnel "$@"
}
