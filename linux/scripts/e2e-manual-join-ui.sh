#!/usr/bin/env bash
# Drive both shipped GTK manual-join roles and prove the signed roster remains
# queued without changing Direct-mode routing. Runtime delivery is exercised
# between this exact Linux release and the physical Pixel later in the gate;
# two daemons on one OS would correctly violate the production singleton.
set -euo pipefail

ROOT_DIR="$(
  cd "${NVPN_REPO_ROOT:-$(dirname "${BASH_SOURCE[0]}")/../..}"
  pwd -P
)"
LINUX_DIR="$ROOT_DIR/linux"
ARTIFACT_DIR="${ARTIFACT_ROOT:-$ROOT_DIR/artifacts/linux-manual-join-ui}"
E2E_ROOT="/tmp/nostr-vpn-linux-manual-join-ui"
ADMIN_DATA_DIR="$E2E_ROOT/admin"
JOINER_DATA_DIR="$E2E_ROOT/joiner"
RESULT="$ARTIFACT_DIR/result.json"
APP_LOG="$ARTIFACT_DIR/app.log"
TIMEOUT_SECS="${NVPN_DESKTOP_MANUAL_JOIN_TIMEOUT_SECS:-20}"
LINUX_CARGO_TARGET_DIR="${NVPN_LINUX_CARGO_TARGET_DIR:-$LINUX_DIR/target}"
ROOT_CARGO_TARGET_DIR="${NVPN_ROOT_CARGO_TARGET_DIR:-$LINUX_CARGO_TARGET_DIR}"
FIXTURE="${NVPN_LINUX_FIXTURE_PATH:-$ROOT_CARGO_TARGET_DIR/debug/examples/desktop_manual_join_e2e_fixture}"
NVPN="${NVPN_LINUX_NVPN_PATH:-$ROOT_CARGO_TARGET_DIR/debug/nvpn}"
APP="${NVPN_LINUX_APP_PATH:-$LINUX_CARGO_TARGET_DIR/debug/nostr-vpn}"
EXPLICIT_ARTIFACT_COUNT=0
[[ -z "${NVPN_LINUX_FIXTURE_PATH:-}" ]] || ((EXPLICIT_ARTIFACT_COUNT += 1))
[[ -z "${NVPN_LINUX_NVPN_PATH:-}" ]] || ((EXPLICIT_ARTIFACT_COUNT += 1))
[[ -z "${NVPN_LINUX_APP_PATH:-}" ]] || ((EXPLICIT_ARTIFACT_COUNT += 1))
[[ "$EXPLICIT_ARTIFACT_COUNT" == 0 || "$EXPLICIT_ARTIFACT_COUNT" == 3 ]] || {
  echo "Set all three explicit Linux app, CLI, and fixture paths together." >&2
  exit 2
}
cargo_config_args=()
app_pid=""
window_id=""

if [[ -n "${NVPN_FIPS_REPO_PATH:-}" ]]; then
  cargo_config_args+=(
    --config "patch.crates-io.nvpn-fips-core.path=\"$NVPN_FIPS_REPO_PATH/crates/fips-core\""
    --config "patch.crates-io.nvpn-fips-endpoint.path=\"$NVPN_FIPS_REPO_PATH/crates/fips-endpoint\""
    --config "patch.crates-io.nvpn-fips-identity.path=\"$NVPN_FIPS_REPO_PATH/crates/fips-identity\""
  )
fi

cargo_run() {
  if ((${#cargo_config_args[@]})); then
    cargo "${cargo_config_args[@]}" "$@"
  else
    cargo "$@"
  fi
}

fixture_args=(
  --admin-data-dir "$ADMIN_DATA_DIR"
  --joiner-data-dir "$JOINER_DATA_DIR"
  --result "$RESULT"
)

stop_app() {
  if [[ -n "$app_pid" ]] && kill -0 "$app_pid" >/dev/null 2>&1; then
    kill "$app_pid" >/dev/null 2>&1 || true
    wait "$app_pid" >/dev/null 2>&1 || true
  fi
  app_pid=""
  window_id=""
  # A manual join starts the real approval transport. Stop only daemons whose
  # command line names one of this fixture's isolated config directories.
  pkill -f "nvpn.*$E2E_ROOT" >/dev/null 2>&1 || true
}

cleanup() {
  stop_app
}
trap cleanup EXIT

rm -rf "$E2E_ROOT"
mkdir -p "$ARTIFACT_DIR" "$E2E_ROOT"
rm -f "$RESULT" "$APP_LOG" "$ARTIFACT_DIR"/*.png

cd "$ROOT_DIR"

sudo -n true >/dev/null 2>&1 || {
  echo "Linux real manual-join runtime gate requires passwordless sudo on the isolated VM." >&2
  exit 1
}

snapshot_default_route() {
  ip -j route show default | jq -S .
}

snapshot_dns() {
  if command -v resolvectl >/dev/null 2>&1 && resolvectl dns >/dev/null 2>&1; then
    # Ignore address-only tunnel links that have no resolver assignment.
    resolvectl dns |
      awk -F': ' 'NF >= 2 && length($2) > 0 { print }' |
      sort
  else
    cat /etc/resolv.conf
  fi
}

assert_direct_internet() {
  curl --fail --silent --show-error --max-time 8 \
    --output /dev/null https://connectivitycheck.gstatic.com/generate_204
}

snapshot_default_route >"$ARTIFACT_DIR/default-route-before.json"
snapshot_dns >"$ARTIFACT_DIR/dns-before.txt"
assert_direct_internet

case "$EXPLICIT_ARTIFACT_COUNT:${NVPN_DESKTOP_MANUAL_JOIN_SKIP_BUILD:-0}" in
  3:*)
    for executable in "$FIXTURE" "$NVPN" "$APP"; do
      [[ -x "$executable" ]] || {
        echo "Imported Linux manual-join executable is missing: $executable" >&2
        exit 1
      }
    done
    ;;
  0:1|0:true|0:TRUE|0:True|0:yes|0:YES|0:Yes|0:on|0:ON|0:On)
    for executable in "$FIXTURE" "$NVPN" "$APP"; do
      [[ -x "$executable" ]] || {
        echo "Prebuilt Linux manual-join executable is missing: $executable" >&2
        exit 1
      }
    done
    ;;
  0:*)
    CARGO_TARGET_DIR="$ROOT_CARGO_TARGET_DIR" \
      cargo_run build -q -p nvpn
    CARGO_TARGET_DIR="$ROOT_CARGO_TARGET_DIR" \
      cargo_run build -q -p nostr-vpn-core \
        --example desktop_manual_join_e2e_fixture
    cd "$LINUX_DIR"
    CARGO_TARGET_DIR="$LINUX_CARGO_TARGET_DIR" cargo_run build -q
    ;;
esac
"$FIXTURE" prepare "${fixture_args[@]}"

read_metadata() {
  python3 - "$RESULT" "$1" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])
PY
}

ADMIN_NPUB="$(read_metadata adminNpub)"
JOINER_NPUB="$(read_metadata joinerNpub)"
MESH_NETWORK_ID="$(read_metadata meshNetworkId)"
JOINER_ALIAS="$(read_metadata joinerAlias)"

export DISPLAY="${DISPLAY:-:99}"
export GDK_BACKEND="${GDK_BACKEND:-x11}"
export GTK_A11Y=atspi
export NO_AT_BRIDGE=0

wait_for_window() {
  local deadline=$((SECONDS + TIMEOUT_SECS))
  while ((SECONDS < deadline)); do
    window_id="$(
      xdotool search --onlyvisible --pid "$app_pid" --name "^Nostr VPN$" \
        2>/dev/null | head -n 1 || true
    )"
    if [[ -n "$window_id" ]]; then
      return 0
    fi
    if ! kill -0 "$app_pid" >/dev/null 2>&1; then
      echo "Linux manual-join UI app exited before showing a window." >&2
      tail -n 120 "$APP_LOG" >&2 || true
      return 1
    fi
    sleep 0.1
  done
  echo "Linux manual-join UI window did not appear within ${TIMEOUT_SECS}s." >&2
  return 1
}

wait_for_fixture() {
  local command="$1"
  local label="$2"
  local deadline=$((SECONDS + TIMEOUT_SECS))
  while ((SECONDS < deadline)); do
    if "$FIXTURE" "$command" "${fixture_args[@]}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$app_pid" >/dev/null 2>&1; then
      echo "Linux app exited before persisting the $label manual-join action." >&2
      tail -n 120 "$APP_LOG" >&2 || true
      return 1
    fi
    sleep 0.1
  done
  import -window root "$ARTIFACT_DIR/$label-failure.png" >/dev/null 2>&1 || true
  "$FIXTURE" "$command" "${fixture_args[@]}"
  echo "Linux UI did not persist the $label manual-join action within ${TIMEOUT_SECS}s." >&2
  return 1
}

launch_app() {
  local data_dir="$1"
  NVPN_APP_DATA_DIR="$data_dir" \
    NVPN_CLI_PATH="$NVPN" \
    "$APP" >>"$APP_LOG" 2>&1 &
  app_pid=$!
  wait_for_window
}

launch_app "$JOINER_DATA_DIR"
python3 "$ROOT_DIR/scripts/desktop-manual-join-atspi.py" joiner \
  --pid "$app_pid" \
  --window-id "$window_id" \
  --admin-npub "$ADMIN_NPUB" \
  --mesh-network-id "$MESH_NETWORK_ID"
wait_for_fixture verify-joiner joiner
import -window root "$ARTIFACT_DIR/joiner.png"
stop_app

launch_app "$ADMIN_DATA_DIR"
python3 "$ROOT_DIR/scripts/desktop-manual-join-atspi.py" admin \
  --pid "$app_pid" \
  --window-id "$window_id" \
  --joiner-npub "$JOINER_NPUB" \
  --joiner-alias "$JOINER_ALIAS"
wait_for_fixture verify-admin admin
import -window root "$ARTIFACT_DIR/admin.png"
"$FIXTURE" capture-delivery "${fixture_args[@]}"
stop_app

snapshot_default_route >"$ARTIFACT_DIR/default-route-after.json"
snapshot_dns >"$ARTIFACT_DIR/dns-after.txt"
cmp -s "$ARTIFACT_DIR/default-route-before.json" "$ARTIFACT_DIR/default-route-after.json" || {
  echo "Linux manual join changed the device's default route in Direct mode." >&2
  diff -u "$ARTIFACT_DIR/default-route-before.json" \
    "$ARTIFACT_DIR/default-route-after.json" >&2 || true
  exit 1
}
cmp -s "$ARTIFACT_DIR/dns-before.txt" "$ARTIFACT_DIR/dns-after.txt" || {
  echo "Linux manual join changed device DNS in Direct mode." >&2
  diff -u "$ARTIFACT_DIR/dns-before.txt" "$ARTIFACT_DIR/dns-after.txt" >&2 || true
  exit 1
}
assert_direct_internet

for iface in nvpnmj-joiner nvpnmj-admin; do
  if ip link show "$iface" >/dev/null 2>&1; then
    echo "Linux manual-join cleanup left tunnel interface $iface behind." >&2
    exit 1
  fi
done
if sudo -n pgrep -af nvpn | grep -F -- "$ADMIN_DATA_DIR/config.toml" >/dev/null \
  || sudo -n pgrep -af nvpn | grep -F -- "$JOINER_DATA_DIR/config.toml" >/dev/null
then
  echo "Linux manual-join cleanup left an isolated nvpn daemon running." >&2
  sudo -n pgrep -af nvpn >&2 || true
  exit 1
fi

echo "LINUX_DESKTOP_MANUAL_JOIN_UI_E2E_OK"
echo "Result: $RESULT"
