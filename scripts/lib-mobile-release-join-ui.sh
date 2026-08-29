#!/usr/bin/env bash

# Public accessibility-tree drivers for the signed Release join gate. This
# library never passes join state to an application. The screenshot importer is
# enabled by one target-app launch flag inside its exact XCTest only.

RELEASE_JOIN_ANDROID_UI_XML=""
RELEASE_JOIN_IOS_TEST_PID=""
RELEASE_JOIN_IOS_TEST_PGID=""
RELEASE_JOIN_IOS_TEST_LOG=""
RELEASE_JOIN_IOS_TEST_NAME=""
RELEASE_JOIN_IOS_APP_BUNDLE_ID=""
RELEASE_JOIN_QR_CONTENT_WIDTH_MIN_BPS=9800
RELEASE_JOIN_QR_CONTENT_WIDTH_MAX_BPS=10000
RELEASE_JOIN_ANDROID_QR_CONTENT_WIDTH_BPS=""
RELEASE_JOIN_ANDROID_NETWORK_IDS=()

release_join_desktop_mode() {
  local phase="$1" configured="$2"
  case "$phase" in
    desktop-only) printf '1\n' ;;
    full)
      case "$configured" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On) printf '1\n' ;;
        0|false|FALSE|False|no|NO|No|off|OFF|Off) printf '0\n' ;;
        *) return 2 ;;
      esac
      ;;
    *) printf '0\n' ;;
  esac
}

release_join_marker_value_from_log() {
  local log="$1" name="$2"
  sed -n "s/.*NVPN_RELEASE_JOIN_MARKER $name=//p" "$log" \
    | tail -n 1 | tr -d '\r'
}

release_join_now_ms() {
  python3 - <<'PY'
import time
print(time.time_ns() // 1_000_000)
PY
}

# Run one public-UI poll without allowing a stuck adb/SSH query to outlive the
# phase's absolute deadline.
release_join_run_until_ms() {
  local deadline_ms="$1" label="$2"
  shift 2
  local now_ms remaining_ms delay marker pid watchdog status=0
  now_ms="$(release_join_now_ms)"
  remaining_ms=$((deadline_ms - now_ms))
  ((remaining_ms > 0)) || return 124
  printf -v delay '%d.%03d' \
    "$((remaining_ms / 1000))" "$((remaining_ms % 1000))"
  marker="$(mktemp "${PRIVATE_DIR:-${TMPDIR:-/tmp}}/join-poll.XXXXXX")"
  rm -f "$marker"
  "$@" &
  pid=$!
  (
    sleep "$delay"
    if kill -0 "$pid" >/dev/null 2>&1; then
      : >"$marker"
      pkill -TERM -P "$pid" >/dev/null 2>&1 || true
      kill -TERM "$pid" >/dev/null 2>&1 || true
      sleep 0.2
      pkill -KILL -P "$pid" >/dev/null 2>&1 || true
      kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
  ) 2>/dev/null &
  watchdog=$!
  wait "$pid" || status=$?
  pkill -TERM -P "$watchdog" >/dev/null 2>&1 || true
  kill "$watchdog" >/dev/null 2>&1 || true
  wait "$watchdog" >/dev/null 2>&1 || true
  if [[ -e "$marker" ]]; then
    rm -f "$marker"
    echo "$label exceeded the shared acceptance deadline" >&2
    return 124
  fi
  rm -f "$marker"
  return "$status"
}

release_join_observe_until_ms() {
  local deadline_ms="$1" timestamp_file="$2" label="$3"
  shift 3
  local detected_ms status
  while (( $(release_join_now_ms) < deadline_ms )); do
    status=0
    detected_ms="$(release_join_run_until_ms "$deadline_ms" "$label" "$@")" \
      || status=$?
    if ((status == 0)); then
      detected_ms="${detected_ms##*$'\n'}"
      [[ "$detected_ms" =~ ^[0-9]+$ ]] || {
        echo "$label did not report its state-observation timestamp" >&2
        return 1
      }
      ((detected_ms <= deadline_ms)) || {
        echo "$label observed acceptance after the shared deadline" >&2
        return 1
      }
      printf '%s\n' "$detected_ms" >"$timestamp_file"
      return 0
    fi
    ((status != 124)) || return 1
    sleep 0.1
  done
  return 1
}

release_join_android_accepted_snapshot_ms() {
  local participant="$1" snapshot_ms
  release_join_android_dump_ui || return 1
  snapshot_ms="$(release_join_now_ms)"
  release_join_android_query_dumped \
    resource "roster-participant-accepted-$participant" center \
    >/dev/null 2>&1 || return 1
  printf '%s\n' "$snapshot_ms"
}

release_join_observe_pair_until_ms() {
  local deadline_ms="$1" left_file="$2" left_label="$3"
  local left_callback="$4" left_arg="$5" right_file="$6" right_label="$7"
  local right_callback="$8" right_arg="$9" left_pid right_pid result=0
  release_join_observe_until_ms \
    "$deadline_ms" "$left_file" "$left_label" "$left_callback" "$left_arg" &
  left_pid=$!
  release_join_observe_until_ms \
    "$deadline_ms" "$right_file" "$right_label" "$right_callback" "$right_arg" &
  right_pid=$!
  # shellcheck disable=SC2034 # consumed by each platform cleanup trap
  acceptance_observer_pids=("$left_pid" "$right_pid")
  wait "$left_pid" || result=1
  wait "$right_pid" || result=1
  # shellcheck disable=SC2034 # consumed by each platform cleanup trap
  acceptance_observer_pids=()
  return "$result"
}

release_join_android_dump_ui() {
  RELEASE_JOIN_ANDROID_UI_XML="$PRIVATE_DIR/android-ui.xml"
  "${ADB[@]}" shell uiautomator dump /sdcard/nvpn-release-join.xml >/dev/null 2>&1
  "${ADB[@]}" exec-out cat /sdcard/nvpn-release-join.xml \
    >"$RELEASE_JOIN_ANDROID_UI_XML"
}

release_join_android_query() {
  local kind="$1" expected="$2" output="$3"
  release_join_android_dump_ui
  release_join_android_query_dumped "$kind" "$expected" "$output"
}

release_join_android_query_dumped() {
  local kind="$1" expected="$2" output="$3"
  "$ROOT/scripts/mobile-release-join-ui-query.py" \
    "$RELEASE_JOIN_ANDROID_UI_XML" "$kind" "$expected" "$output"
}

release_join_android_wait_query() {
  local kind="$1" expected="$2" timeout="${3:-$RELEASE_JOIN_UI_WAIT_SECS}"
  local deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if release_join_android_query "$kind" "$expected" center >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

release_join_android_tap() {
  local kind="$1" expected="$2" point
  point="$(release_join_android_query "$kind" "$expected" safe-center)" || return 1
  # shellcheck disable=SC2086
  "${ADB[@]}" shell input tap $point
}

release_join_android_tap_visible() {
  local kind="$1" expected="$2" point
  point="$(release_join_android_query "$kind" "$expected" visible-center)" \
    || return 1
  # shellcheck disable=SC2086
  "${ADB[@]}" shell input tap $point
}

release_join_android_scroll() {
  local size width height
  size="$("${ADB[@]}" shell wm size | tr -d '\r' | sed -n 's/^Physical size: //p')"
  width="${size%x*}"
  height="${size#*x}"
  "${ADB[@]}" shell input swipe \
    "$((width / 2))" "$((height * 4 / 5))" \
    "$((width / 2))" "$((height / 3))" 220
}

release_join_android_scroll_to() {
  local kind="$1" expected="$2" visibility="${3:-safe-center}"
  local attempts
  case "$visibility" in
    safe-center|visible-center) ;;
    *) return 2 ;;
  esac
  for ((attempts = 0; attempts < 12; attempts++)); do
    if release_join_android_query \
        "$kind" "$expected" "$visibility" >/dev/null 2>&1
    then
      return 0
    fi
    release_join_android_scroll >/dev/null
    sleep 0.2
  done
  return 1
}

release_join_android_enter() {
  local kind="$1" selector="$2" value="$3"
  local visibility="${4:-safe-center}"
  local actual deadline input_state
  release_join_android_scroll_to "$kind" "$selector" "$visibility" || return 1
  if [[ "$visibility" == visible-center ]]; then
    release_join_android_tap_visible "$kind" "$selector" || return 1
  else
    release_join_android_tap "$kind" "$selector" || return 1
  fi
  deadline=$((SECONDS + 3))
  while ((SECONDS < deadline)); do
    input_state="$("${ADB[@]}" shell dumpsys input_method | tr -d '\r')" \
      || return 1
    if grep -Fq 'mInputShown=true' <<<"$input_state"; then
      break
    fi
    sleep 0.1
  done
  grep -Fq 'mInputShown=true' <<<"$input_state" || {
    echo "Android join field did not open the system input method: $selector" >&2
    return 1
  }
  "${ADB[@]}" shell input keycombination -t 40 KEYCODE_CTRL_LEFT KEYCODE_A \
    || return 1
  "${ADB[@]}" shell input keyevent KEYCODE_DEL || return 1
  "${ADB[@]}" shell input text "${value// /%s}" </dev/null || return 1
  "${ADB[@]}" shell input keyevent KEYCODE_BACK || return 1
  deadline=$((SECONDS + 3))
  while ((SECONDS < deadline)); do
    actual="$(release_join_android_query text "$value" text 2>/dev/null || true)"
    [[ "$actual" == "$value" ]] && return 0
    sleep 0.1
  done
  echo "Android join field did not retain exact text: $selector" >&2
  return 1
}

release_join_android_launch() {
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"
  "${ADB[@]}" shell am start -W \
    --ez org.nostrvpn.app.extra.RELEASE_JOIN_IMAGE_IMPORT true \
    -n "$package/org.nostrvpn.app.MainActivity" >/dev/null
}

release_join_android_tap_center() {
  local kind="$1" expected="$2" point
  point="$(
    release_join_android_query "$kind" "$expected" center 2>/dev/null
  )" || return 1
  # Permission sheets and confirmation dialogs can sit below the guarded
  # scrolling-app viewport.
  # shellcheck disable=SC2086
  "${ADB[@]}" shell input tap $point
}

release_join_android_tap_system_resource() {
  release_join_android_tap_center resource "$1"
}

release_join_android_top_activity() {
  "${ADB[@]}" shell dumpsys activity activities 2>/dev/null \
    | tr -d '\r' \
    | sed -nE \
      's/.*(topResumedActivity|mResumedActivity).* u[0-9]+ ([^ ]+\/[^ ]+) .*/\2/p' \
    | head -n 1
}

release_join_android_wait_through_system_prompts() {
  local kind="$1" expected="$2" timeout="$3"
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"
  local deadline=$((SECONDS + timeout)) activity
  while ((SECONDS < deadline)); do
    activity="$(release_join_android_top_activity)"
    case "$activity" in
      com.android.permissioncontroller/*)
        release_join_android_tap_system_resource \
          "com.android.permissioncontroller:id/permission_allow_foreground_only_button" \
          >/dev/null 2>&1 \
          || release_join_android_tap_system_resource \
            "com.android.permissioncontroller:id/permission_allow_button" \
            >/dev/null 2>&1 \
          || true
        ;;
      com.android.vpndialogs/*)
        release_join_android_tap_system_resource "android:id/button1" \
          >/dev/null 2>&1 || true
        ;;
      *)
        if release_join_android_query "$kind" "$expected" center \
          >/dev/null 2>&1
        then
          sleep 0.25
          [[ "$(release_join_android_top_activity)" == \
            "$package/"* ]] && return 0
        fi
        ;;
    esac
    sleep 0.25
  done
  return 1
}

release_join_android_accept_camera_permission() {
  release_join_android_wait_through_system_prompts \
    description "QR scanner camera" 8
}

release_join_android_accept_join_transport_permissions() {
  release_join_android_wait_through_system_prompts \
    resource manual-join-expand 10 || {
      echo "Android join transport permission did not complete" >&2
      return 1
    }
}

release_join_android_accept_admin_transport_permissions() {
  release_join_android_wait_through_system_prompts \
    description "Open manual device approval" 10 || {
      echo "Android admin transport permission did not complete" >&2
      return 1
    }
}

release_join_android_os_vpn_connected() {
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"
  "${ADB[@]}" shell dumpsys connectivity 2>/dev/null \
    | tr -d '\r' \
    | grep -F "ni{VPN CONNECTED extra: VPN:$package}" >/dev/null
}

release_join_android_wait_vpn_connected() {
  local deadline=$((SECONDS + RELEASE_JOIN_UI_WAIT_SECS))
  while ((SECONDS < deadline)); do
    if release_join_android_query description "Turn VPN off" center \
        >/dev/null 2>&1 \
      && release_join_android_os_vpn_connected
    then
      return 0
    fi
    sleep 0.25
  done
  echo "Android admin network did not start its production VPN" >&2
  return 1
}

release_join_android_public_value() {
  local prefix="$1" description
  description="$(
    release_join_android_query description-prefix "$prefix: " description
  )" || return 1
  [[ "$description" == "$prefix: "* ]] || return 1
  printf '%s\n' "${description#"$prefix: "}"
}

release_join_valid_npub() {
  [[ "$1" =~ ^npub1[023456789acdefghjklmnpqrstuvwxyz]{58}$ ]]
}

release_join_android_open_devices() {
  release_join_android_launch
  if release_join_android_query \
      description "Open manual device approval" center >/dev/null 2>&1; then
    return 0
  fi
  release_join_android_wait_query description "Devices tab"
  release_join_android_tap description "Devices tab"
}

release_join_android_open_link_device() {
  release_join_android_launch
  if release_join_android_query \
      description-prefix "Admin Device ID value: " center >/dev/null 2>&1; then
    return 0
  fi
  release_join_android_open_devices
  release_join_android_tap description "Open manual device approval"
  release_join_android_wait_query \
    description-prefix "Admin Device ID value: "
}

release_join_android_create_admin() {
  release_join_android_launch
  release_join_android_wait_query resource network-setup-create
  release_join_android_tap resource network-setup-create
  release_join_android_wait_query resource network-create-submit
  release_join_android_tap resource network-create-submit
  release_join_android_accept_admin_transport_permissions
  release_join_android_wait_vpn_connected
  release_join_android_open_link_device
  RELEASE_JOIN_ANDROID_ADMIN_ID="$(
    release_join_android_public_value "Admin Device ID value"
  )"
  RELEASE_JOIN_ANDROID_NETWORK_ID="$(
    release_join_android_public_value "Admin Network ID value"
  )"
  release_join_valid_npub "$RELEASE_JOIN_ANDROID_ADMIN_ID"
  [[ -n "$RELEASE_JOIN_ANDROID_NETWORK_ID" ]]
  if ((${#RELEASE_JOIN_ANDROID_NETWORK_IDS[@]} > 0)); then
    local existing
    for existing in "${RELEASE_JOIN_ANDROID_NETWORK_IDS[@]}"; do
      [[ "$existing" != "$RELEASE_JOIN_ANDROID_NETWORK_ID" ]] || {
        echo "Android join phase reused a retained network" >&2
        return 1
      }
    done
  fi
  RELEASE_JOIN_ANDROID_NETWORK_IDS+=("$RELEASE_JOIN_ANDROID_NETWORK_ID")
  export RELEASE_JOIN_ANDROID_ADMIN_ID RELEASE_JOIN_ANDROID_NETWORK_ID
}

release_join_android_show_qr() {
  release_join_android_launch
  release_join_android_wait_query resource network-setup-join
  release_join_android_tap resource network-setup-join
  release_join_android_accept_join_transport_permissions
  release_join_android_scroll_to resource manual-join-expand
  release_join_android_tap resource manual-join-expand
  release_join_android_wait_query resource joiner-device-id-value
  RELEASE_JOIN_ANDROID_JOINER_ID="$(
    release_join_android_public_value "Joiner Device ID value"
  )"
  release_join_valid_npub "$RELEASE_JOIN_ANDROID_JOINER_ID"
  release_join_android_scroll_to description "Join request QR code"
  release_join_android_assert_qr_full_width
  export RELEASE_JOIN_ANDROID_JOINER_ID
}

release_join_android_background_foreground_pending_qr() {
  local expected_joiner="$RELEASE_JOIN_ANDROID_JOINER_ID"
  local foreground_joiner
  "${ADB[@]}" shell input keyevent KEYCODE_HOME
  sleep 1
  release_join_android_launch
  release_join_android_scroll_to description "Join request QR code"
  release_join_android_assert_pending_qr
  foreground_joiner="$(
    release_join_android_public_value \
      "Joiner Device ID value"
  )"
  [[ "$foreground_joiner" == "$expected_joiner" ]] || {
    echo "Android foregrounded a different pending join request" >&2
    return 1
  }
  release_join_android_assert_qr_full_width
  RELEASE_JOIN_ANDROID_PENDING_QR_LIFECYCLE_READY=1
  export RELEASE_JOIN_ANDROID_PENDING_QR_LIFECYCLE_READY
  echo "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_ANDROID_PENDING_QR_LIFECYCLE_READY=1"
}

release_join_android_assert_qr_full_width() {
  local qr_width content_width ratio_bps
  release_join_android_dump_ui
  qr_width="$(
    release_join_android_query_dumped \
      description "Join request QR code" width
  )" || return 1
  content_width="$(
    release_join_android_query_dumped \
      resource "join-request-qr-content" width
  )" || return 1
  [[ "$qr_width" =~ ^[1-9][0-9]*$ \
    && "$content_width" =~ ^[1-9][0-9]*$ ]] \
    || return 1
  ratio_bps=$((qr_width * 10000 / content_width))
  ((ratio_bps >= RELEASE_JOIN_QR_CONTENT_WIDTH_MIN_BPS \
    && ratio_bps <= RELEASE_JOIN_QR_CONTENT_WIDTH_MAX_BPS)) || {
    echo "Android join QR does not fill its content width ($qr_width/$content_width px)" >&2
    return 1
  }
  if [[ -z "$RELEASE_JOIN_ANDROID_QR_CONTENT_WIDTH_BPS" ]] \
      || ((ratio_bps < RELEASE_JOIN_ANDROID_QR_CONTENT_WIDTH_BPS))
  then
    RELEASE_JOIN_ANDROID_QR_CONTENT_WIDTH_BPS="$ratio_bps"
  fi
}

release_join_android_assert_pending_qr() {
  release_join_android_query description "Join request QR code" center \
    >/dev/null
  release_join_android_public_value \
    "Joiner Device ID value" \
    | grep -Fxq "$RELEASE_JOIN_ANDROID_JOINER_ID"
}

release_join_android_wait_join_complete() {
  release_join_android_wait_accepted_participant "$1"
}

release_join_android_wait_accepted_participant() {
  local participant="$1" deadline=$((SECONDS + RELEASE_JOIN_DELIVERY_WAIT_SECS))
  while ((SECONDS < deadline)); do
    release_join_android_open_devices >/dev/null 2>&1 || true
    if release_join_android_query \
        resource "roster-participant-accepted-$participant" center \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

release_join_android_relaunch_and_wait_accepted() {
  local participant="$1"
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"
  "${ADB[@]}" shell am force-stop "$package" >/dev/null
  release_join_android_launch >/dev/null
  release_join_android_wait_accepted_participant "$participant"
}

release_join_android_wait_qr_join_complete() {
  local admin="$1" deadline=$((SECONDS + RELEASE_JOIN_DELIVERY_WAIT_SECS))
  local description
  while ((SECONDS < deadline)); do
    release_join_android_launch >/dev/null 2>&1 || true
    release_join_android_dump_ui
    if release_join_android_query_dumped \
        description "Join request QR code" center >/dev/null 2>&1; then
      description="$(
        release_join_android_query_dumped \
          resource joiner-device-id-value description
      )" || return 1
      [[ "$description" == \
        "Joiner Device ID value: $RELEASE_JOIN_ANDROID_JOINER_ID" ]] \
        || return 1
      sleep 0.25
      continue
    fi
    if ! release_join_android_query_dumped \
        resource "roster-participant-accepted-$admin" center >/dev/null 2>&1; then
      echo "Android join QR disappeared before the exact accepted admin roster was visible" >&2
      return 1
    fi
    return 0
  done
  return 1
}

release_join_android_scan_prepare() {
  release_join_android_open_link_device
  RELEASE_JOIN_ANDROID_SCAN_BEFORE="$(
    release_join_android_query resource-prefix roster-participant- count
  )"
  export RELEASE_JOIN_ANDROID_SCAN_BEFORE
  release_join_android_scroll_to description "Scan joining device QR"
  release_join_android_tap description "Scan joining device QR"
  release_join_android_accept_camera_permission
  release_join_android_wait_query description "Import QR Image"
  echo "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_IMPORT_READY=1"
}

release_join_android_scan_submit() {
  local joiner="$1" image="$2" filename after deadline
  [[ "${RELEASE_JOIN_ANDROID_SCAN_BEFORE:-}" =~ ^[0-9]+$ ]] || {
    echo "Android QR image import was not prepared before approval" >&2
    return 1
  }
  [[ -s "$image" ]] || {
    echo "Android QR image import has no captured source image" >&2
    return 1
  }
  filename="$(basename "$image")"
  "${ADB[@]}" push "$image" "/sdcard/Download/$filename" >/dev/null
  "${ADB[@]}" shell am broadcast \
    -a android.intent.action.MEDIA_SCANNER_SCAN_FILE \
    -d "file:///sdcard/Download/$filename" >/dev/null
  release_join_android_wait_query description "Import QR Image"
  release_join_android_tap description "Import QR Image"
  release_join_android_wait_query description-prefix "$filename,"
  release_join_android_tap description-prefix "$filename,"
  release_join_android_wait_query \
    description "Confirm adding scanned join request" \
    "${RELEASE_JOIN_IMPORT_WAIT_SECS:-15}"
  release_join_require_fresh_ios_pending_qr
  echo "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=$(release_join_now_ms)"
  release_join_android_tap_center \
    description "Confirm adding scanned join request"
  release_join_android_wait_through_system_prompts \
    resource "roster-participant-accepted-$joiner" 10 || {
      echo "Android admin transport permission did not complete" >&2
      return 1
    }
  deadline=$((SECONDS + RELEASE_JOIN_DELIVERY_WAIT_SECS))
  while ((SECONDS < deadline)); do
    release_join_android_open_devices >/dev/null 2>&1 || true
    if release_join_android_query \
        resource "roster-participant-accepted-$joiner" center \
        >/dev/null 2>&1; then
      after="$(release_join_android_query resource-prefix roster-participant- count)"
      ((after >= RELEASE_JOIN_ANDROID_SCAN_BEFORE + 1)) || return 1
      return 0
    fi
    sleep 0.25
  done
  return 1
}

release_join_capture_android_qr() {
  local output="$1"
  rm -f "$output"
  "${ADB[@]}" exec-out screencap -p >"$output"
  [[ "$(od -An -tx1 -N8 "$output" | tr -d ' \n')" == 89504e470d0a1a0a ]] || {
    echo "Android QR screen capture is not a PNG" >&2
    return 1
  }
}

release_join_capture_ios_qr() {
  local output="$1"
  local bundle filename expected_sha actual_sha
  rm -f "$output"
  filename="$(
    release_join_ios_marker_value NVPN_RELEASE_JOIN_QR_SCREENSHOT_FILENAME
  )"
  expected_sha="$(
    release_join_ios_marker_value NVPN_RELEASE_JOIN_QR_SCREENSHOT_SHA256
  )"
  [[ "$filename" =~ ^nvpn-release-join-qr-[A-Fa-f0-9-]+\.png$ \
    && "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || {
    echo "iPhone XCTest did not report an exact QR screen capture" >&2
    return 1
  }
  bundle="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}.UITests.xctrunner"
  RELEASE_JOIN_IOS_CAPTURED_QR_FILENAME="$filename"
  export RELEASE_JOIN_IOS_CAPTURED_QR_FILENAME
  xcrun devicectl device copy from \
    --device "$IOS_DEVICE" \
    --domain-type appDataContainer \
    --domain-identifier "$bundle" \
    --source "Documents/$filename" \
    --destination "$output" \
    --timeout 15 \
    --quiet >/dev/null || {
    echo "Could not copy the XCTest QR screen capture from the iPhone" >&2
    return 1
  }
  actual_sha="$(shasum -a 256 "$output" | awk '{print $1}')"
  [[ "$(od -An -tx1 -N8 "$output" 2>/dev/null | tr -d ' \n')" \
      == 89504e470d0a1a0a \
    && "$actual_sha" == "$expected_sha" ]] || {
    rm -f "$output"
    echo "Copied iPhone QR screen capture failed PNG/hash validation" >&2
    return 1
  }
}

release_join_stage_ios_qr_image() {
  local image="$1" filename="$2"
  local app_bundle="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
  local runner_bundle="$app_bundle.UITests.xctrunner"
  local bundle
  RELEASE_JOIN_IOS_STAGED_QR_FILENAME="$filename"
  export RELEASE_JOIN_IOS_STAGED_QR_FILENAME
  for bundle in "$app_bundle" "$runner_bundle"; do
    xcrun devicectl device copy to \
      --device "$IOS_DEVICE" \
      --domain-type appDataContainer \
      --domain-identifier "$bundle" \
      --source "$image" \
      --destination "Documents/$filename" \
      --timeout 15 \
      --quiet >/dev/null || return 1
  done
}

release_join_require_fresh_ios_pending_qr() {
  local deadline=$((SECONDS + 3)) heartbeat fresh
  while ((SECONDS < deadline)); do
    heartbeat="$(
      release_join_ios_marker_value NVPN_RELEASE_JOIN_PENDING_QR_VISIBLE_MS
    )"
    if [[ "$heartbeat" =~ ^[0-9]+$ ]]; then
      sleep 0.2
      fresh="$(
        release_join_ios_marker_value NVPN_RELEASE_JOIN_PENDING_QR_VISIBLE_MS
      )"
      if [[ "$fresh" =~ ^[0-9]+$ ]] && ((fresh > heartbeat)); then
        return 0
      fi
    fi
    sleep 0.1
  done
  echo "iPhone join QR was not visibly pending immediately before Android approval" >&2
  return 1
}

release_join_android_manual_submit() {
  local admin="$1" network="$2"
  release_join_android_launch
  release_join_android_wait_query resource network-setup-join
  release_join_android_tap resource network-setup-join
  release_join_android_accept_join_transport_permissions
  release_join_android_scroll_to resource manual-join-expand
  release_join_android_tap resource manual-join-expand
  release_join_android_wait_query resource joiner-device-id-value
  RELEASE_JOIN_ANDROID_JOINER_ID="$(
    release_join_android_public_value "Joiner Device ID value"
  )"
  release_join_valid_npub "$RELEASE_JOIN_ANDROID_JOINER_ID"
  release_join_android_enter resource manual-join-admin-id "$admin"
  release_join_android_enter \
    resource manual-join-network-id "$network" visible-center
  release_join_android_wait_query resource manual-join-submit
  release_join_android_tap_center resource manual-join-submit
  local deadline=$((SECONDS + 3))
  while ((SECONDS < deadline)); do
    if ! release_join_android_query resource manual-join-submit center >/dev/null 2>&1; then
      echo "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_MANUAL_SUBMITTED=1"
      export RELEASE_JOIN_ANDROID_JOINER_ID
      return 0
    fi
    sleep 0.1
  done
  echo "Android manual join submit did not change the shipped UI" >&2
  return 1
}

release_join_android_admin_add_visible() {
  local joiner="$1"
  release_join_android_dump_ui || return 1
  if release_join_android_query_dumped \
      description "Add joining device manually" center >/dev/null 2>&1
  then
    return 1
  fi
  release_join_android_query_dumped \
      resource "roster-participant-pending-$joiner" center >/dev/null 2>&1 \
    || release_join_android_query_dumped \
      resource "roster-participant-accepted-$joiner" center >/dev/null 2>&1
}

release_join_android_manual_admin_prepare() {
  local joiner="$1" enabled
  release_join_android_open_link_device
  RELEASE_JOIN_ANDROID_ADMIN_ADD_BEFORE="$(
    release_join_android_query resource-prefix roster-participant- count
  )"
  release_join_android_scroll_to description "Manual joiner Device ID"
  release_join_android_enter description "Manual joiner Device ID" "$joiner"
  release_join_android_scroll_to \
    description "Add joining device manually" visible-center
  release_join_android_query text "$joiner" center >/dev/null 2>&1 || {
    echo "Android manual admin-add Device ID did not remain populated" >&2
    return 1
  }
  enabled="$(
    release_join_android_query description "Add joining device manually" enabled
  )" || return 1
  [[ "$enabled" == true ]] || {
    echo "Android manual admin-add remained disabled after valid input" >&2
    return 1
  }
  RELEASE_JOIN_ANDROID_ADMIN_ADD_JOINER="$joiner"
  export RELEASE_JOIN_ANDROID_ADMIN_ADD_BEFORE \
    RELEASE_JOIN_ANDROID_ADMIN_ADD_JOINER
  echo "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_ADMIN_ADD_PREPARED=1"
}

release_join_android_manual_admin_tap() {
  local joiner="$1" deadline enabled submitted_ms
  local submitted_visible=0
  [[ "${RELEASE_JOIN_ANDROID_ADMIN_ADD_JOINER:-}" == "$joiner" \
    && "${RELEASE_JOIN_ANDROID_ADMIN_ADD_BEFORE:-}" =~ ^[0-9]+$ ]] || {
    echo "Android manual admin-add was not prepared for this exact joiner" >&2
    return 1
  }
  release_join_android_query text "$joiner" center >/dev/null 2>&1 \
    || return 1
  enabled="$(
    release_join_android_query description "Add joining device manually" enabled
  )" || return 1
  [[ "$enabled" == true ]] || {
    echo "Android prepared admin-add controls changed before submission" >&2
    return 1
  }
  submitted_ms="$(release_join_now_ms)"
  release_join_android_tap_visible \
    description "Add joining device manually" || return 1
  deadline=$((SECONDS + 3))
  while ((SECONDS < deadline)); do
    if release_join_android_admin_add_visible "$joiner"; then
      echo "NVPN_RELEASE_JOIN_MARKER NVPN_RELEASE_JOIN_APPROVAL_SUBMITTED_MS=$submitted_ms"
      submitted_visible=1
      break
    fi
    sleep 0.1
  done
  if ((submitted_visible != 1)); then
    echo "Android manual admin-add tap did not visibly submit" >&2
    return 1
  fi
}

release_join_android_manual_admin_wait_accepted() {
  local joiner="$1" after deadline
  deadline=$((SECONDS + RELEASE_JOIN_DELIVERY_WAIT_SECS))
  while ((SECONDS < deadline)); do
    release_join_android_open_devices >/dev/null 2>&1 || true
    if release_join_android_query \
        resource "roster-participant-accepted-$joiner" center \
        >/dev/null 2>&1; then
      after="$(release_join_android_query resource-prefix roster-participant- count)"
      ((after >= RELEASE_JOIN_ANDROID_ADMIN_ADD_BEFORE + 1)) || return 1
      return 0
    fi
    sleep 0.25
  done
  return 1
}

release_join_android_manual_admin_submit() {
  local joiner="$1"
  release_join_android_manual_admin_tap "$joiner"
  release_join_android_manual_admin_wait_accepted "$joiner"
}

release_join_android_manual_admin_add() {
  local joiner="$1"
  release_join_android_manual_admin_prepare "$joiner"
  release_join_android_manual_admin_submit "$joiner"
}

release_join_ios_test_command() {
  local test_name="$1"
  shift
  local bundle="${RELEASE_JOIN_IOS_APP_BUNDLE_ID:-${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}}"
  if ! release_join_reuse_artifacts; then
    echo "iOS release join requires the frozen xctestrun artifact" >&2
    return 1
  fi
  local case_dir case_xctestrun
  local -a command=() rewrite_command=() runner_environment=()
  if ! case_dir="$(
    mktemp -d "$PRIVATE_DIR/join-$test_name.XXXXXX"
  )"; then
    return 1
  fi
  case_xctestrun="$case_dir/case.xctestrun"
  rewrite_command=(
    python3 "$ROOT/scripts/ios_frozen_archive.py"
    rewrite-xctestrun
    --source "$RELEASE_JOIN_IOS_XCTESTRUN"
    --output "$case_xctestrun"
    --products-root "$RELEASE_JOIN_IOS_DERIVED_DATA/Build/Products"
    --target-app "$RELEASE_JOIN_IOS_APP_PATH"
    --use-destination-artifacts
    --environment-stdin0
  )
  runner_environment=(
    "NVPN_RELEASE_JOIN_ADMIN_ID="
    "NVPN_RELEASE_JOIN_BLACKBOX="
    "NVPN_RELEASE_JOIN_DELIVERY_WAIT_SECS="
    "NVPN_RELEASE_JOIN_IMAGE_FILENAME="
    "NVPN_RELEASE_JOIN_IMPORT_WAIT_SECS="
    "NVPN_RELEASE_JOIN_JOINER_ID="
    "NVPN_RELEASE_JOIN_NETWORK_ID="
    "NVPN_RELEASE_JOIN_NETWORK_NAME="
    "NVPN_RELEASE_JOIN_SETUP_WAIT_SECS="
    "NVPN_IOS_BUNDLE_ID="
    "NVPN_RELEASE_JOIN_BLACKBOX=1"
    "NVPN_RELEASE_JOIN_DELIVERY_WAIT_SECS=$RELEASE_JOIN_DELIVERY_WAIT_SECS"
    "NVPN_RELEASE_JOIN_IMPORT_WAIT_SECS=${RELEASE_JOIN_IMPORT_WAIT_SECS:-15}"
    "NVPN_RELEASE_JOIN_SETUP_WAIT_SECS=$RELEASE_JOIN_IOS_SETUP_WAIT_SECS"
    "NVPN_IOS_BUNDLE_ID=$bundle"
  )
  local assignment
  for assignment in "$@"; do
    runner_environment+=("$assignment")
  done
  if ! printf '%s\0' "${runner_environment[@]}" \
    | "${rewrite_command[@]}"
  then
    rm -f "$case_xctestrun"
    rmdir "$case_dir" || true
    return 1
  fi
  command=(
    xcodebuild
    -xctestrun "$case_xctestrun"
    -destination "platform=iOS,id=$RELEASE_JOIN_IOS_UDID,arch=arm64"
    -destination-timeout 60
    -collect-test-diagnostics never
    -parallel-testing-enabled NO
    -only-testing:"NostrVpnIosUITests/NostrVpnReleaseJoinUITests/$test_name"
  )
  command+=(test-without-building)
  printf '%s\0' "${command[@]}"
}

release_join_ios_process_pgid() {
  ps -o pgid= -p "$1" 2>/dev/null | tr -d '[:space:]'
}

release_join_ios_stop_runner() {
  local device="${IOS_DEVICE:-${RELEASE_JOIN_IOS_UDID:-}}"
  local bundle="${RELEASE_JOIN_IOS_APP_BUNDLE_ID:-${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}}"
  [[ -n "$device" ]] || return 1
  IOS_BUNDLE_ID="$bundle" \
    ios_release_network_stop_forced_xctrunner "$device"
}

release_join_ios_start_test() {
  local test_name="$1" log="$2"
  shift 2
  local -a command=()
  local command_file pid pgid actual_pgid caller_pgid cleanup_status=0
  local monitor_was_enabled=0
  RELEASE_JOIN_IOS_APP_BUNDLE_ID="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
  command_file="$(mktemp "$PRIVATE_DIR/ios-command.XXXXXX")"
  if ! release_join_ios_test_command "$test_name" "$@" >"$command_file"; then
    rm -f "$command_file"
    return 1
  fi
  while IFS= read -r -d '' item; do
    command+=("$item")
  done <"$command_file"
  rm -f "$command_file"
  [[ "${#command[@]}" -gt 0 ]] || return 1
  mkdir -p "$(dirname "$log")"
  [[ "$-" == *m* ]] && monitor_was_enabled=1
  set -m
  (exec "${command[@]}") >"$log" 2>&1 &
  pid=$!
  ((monitor_was_enabled)) || set +m
  pgid="$pid"
  actual_pgid="$(release_join_ios_process_pgid "$pid" || true)"
  caller_pgid="$(ps -o pgid= -p "$$" 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "$actual_pgid" != "$pgid" || "$pgid" == "$caller_pgid" ]]; then
    ios_release_network_terminate_process_group "$pgid" || cleanup_status=1
    if [[ "$actual_pgid" =~ ^[1-9][0-9]*$ \
        && "$actual_pgid" != "$pgid" \
        && "$actual_pgid" != "$caller_pgid" ]]; then
      ios_release_network_terminate_process_group "$actual_pgid" \
        || cleanup_status=1
    fi
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
    if ios_release_network_process_group_alive "$pgid" \
        || { [[ "$actual_pgid" =~ ^[1-9][0-9]*$ \
          && "$actual_pgid" != "$caller_pgid" ]] \
          && ios_release_network_process_group_alive "$actual_pgid"; }; then
      cleanup_status=1
    fi
    release_join_ios_stop_runner || cleanup_status=1
    echo "iOS join test did not receive an isolated process group" >&2
    ((cleanup_status == 0)) \
      || echo "iOS join test isolation-failure cleanup was incomplete" >&2
    return 2
  fi
  RELEASE_JOIN_IOS_TEST_PID="$pid"
  RELEASE_JOIN_IOS_TEST_PGID="$pgid"
  RELEASE_JOIN_IOS_TEST_LOG="$log"
  RELEASE_JOIN_IOS_TEST_NAME="$test_name"
  if ! release_join_ios_wait_selected_test_started \
      "${RELEASE_JOIN_IOS_LAUNCH_WAIT_SECS:-60}"; then
    release_join_ios_abort_test || true
    return 1
  fi
}

release_join_ios_abort_test() {
  local status=0 pid="$RELEASE_JOIN_IOS_TEST_PID" pgid="$RELEASE_JOIN_IOS_TEST_PGID"
  if [[ "$pgid" =~ ^[1-9][0-9]*$ ]]; then
    ios_release_network_terminate_process_group "$pgid" || status=1
  elif [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
    kill "$pid" >/dev/null 2>&1 || true
  fi
  if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
    wait "$pid" >/dev/null 2>&1 || true
  fi
  if [[ "$pgid" =~ ^[1-9][0-9]*$ ]] \
      && ios_release_network_process_group_alive "$pgid"; then
    status=1
  fi
  RELEASE_JOIN_IOS_TEST_PID=""
  RELEASE_JOIN_IOS_TEST_PGID=""
  RELEASE_JOIN_IOS_TEST_NAME=""
  release_join_ios_stop_runner || status=1
  return "$status"
}

release_join_ios_assert_selected_test_started() {
  local expected="Test Case '-[NostrVpnIosUITests.NostrVpnReleaseJoinUITests $RELEASE_JOIN_IOS_TEST_NAME]' started."
  grep -Fq "$expected" "$RELEASE_JOIN_IOS_TEST_LOG" || {
    echo "iOS join xcodebuild selected zero tests: $RELEASE_JOIN_IOS_TEST_NAME" >&2
    tail -n 120 "$RELEASE_JOIN_IOS_TEST_LOG" >&2 || true
    return 1
  }
}

release_join_ios_wait_selected_test_started() {
  local timeout="${1:-${RELEASE_JOIN_IOS_LAUNCH_WAIT_SECS:-60}}"
  local expected="Test Case '-[NostrVpnIosUITests.NostrVpnReleaseJoinUITests $RELEASE_JOIN_IOS_TEST_NAME]' started."
  local deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if grep -Fq "$expected" "$RELEASE_JOIN_IOS_TEST_LOG" 2>/dev/null; then
      return 0
    fi
    if [[ -n "$RELEASE_JOIN_IOS_TEST_PID" ]] \
        && ! kill -0 "$RELEASE_JOIN_IOS_TEST_PID" 2>/dev/null; then
      echo "iOS join test exited before XCTest started: $RELEASE_JOIN_IOS_TEST_NAME" >&2
      tail -n 160 "$RELEASE_JOIN_IOS_TEST_LOG" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  echo "iOS join XCTest launch timed out after ${timeout}s: $RELEASE_JOIN_IOS_TEST_NAME" >&2
  tail -n 160 "$RELEASE_JOIN_IOS_TEST_LOG" >&2 || true
  return 1
}

release_join_ios_wait_marker() {
  local marker="$1" timeout="${2:-$RELEASE_JOIN_UI_WAIT_SECS}"
  local deadline=$((SECONDS + timeout))
  while ((SECONDS < deadline)); do
    if grep -Fq "NVPN_RELEASE_JOIN_MARKER $marker" "$RELEASE_JOIN_IOS_TEST_LOG" \
        2>/dev/null; then
      return 0
    fi
    if [[ -n "$RELEASE_JOIN_IOS_TEST_PID" ]] \
        && ! kill -0 "$RELEASE_JOIN_IOS_TEST_PID" 2>/dev/null; then
      release_join_ios_abort_test || true
      echo "iOS join test exited before marker: $marker" >&2
      tail -n 160 "$RELEASE_JOIN_IOS_TEST_LOG" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  echo "iOS join marker timed out after ${timeout}s: $marker" >&2
  tail -n 160 "$RELEASE_JOIN_IOS_TEST_LOG" >&2 || true
  return 1
}

release_join_ios_marker_value() {
  local name="$1"
  release_join_marker_value_from_log "$RELEASE_JOIN_IOS_TEST_LOG" "$name"
}

release_join_ios_finish_test() {
  [[ -n "$RELEASE_JOIN_IOS_TEST_PID" ]] || return 1
  local status=0 pgid="$RELEASE_JOIN_IOS_TEST_PGID"
  wait "$RELEASE_JOIN_IOS_TEST_PID" || status=$?
  RELEASE_JOIN_IOS_TEST_PID=""
  if [[ "$pgid" =~ ^[1-9][0-9]*$ ]] \
      && ios_release_network_process_group_alive "$pgid"; then
    echo "iOS join test left a process-group descendant" >&2
    ios_release_network_terminate_process_group "$pgid" || true
    status=1
  fi
  RELEASE_JOIN_IOS_TEST_PGID=""
  if [[ "$status" -eq 0 ]] \
      && ! release_join_ios_assert_selected_test_started; then
    status=1
  fi
  if [[ "$status" -ne 0 ]]; then
    release_join_ios_stop_runner || status=1
    tail -n 120 "$RELEASE_JOIN_IOS_TEST_LOG" >&2 || true
  fi
  RELEASE_JOIN_IOS_TEST_NAME=""
  return "$status"
}

release_join_ios_run_test() {
  local test_name="$1" log="$2"
  shift 2
  release_join_ios_start_test "$test_name" "$log" "$@"
  release_join_ios_finish_test
}
