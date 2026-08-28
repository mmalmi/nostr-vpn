#!/usr/bin/env bash
# Real macOS launchd service install/uninstall e2e.
#
# Catches the regression class where service install puts the daemon
# binary at a stable path under /Library/PrivilegedHelperTools/, but the
# user-mode CLI's "is the daemon running?" heuristic misses it — leaving
# `nvpn status` reporting daemon.running=false, breaking pause/resume,
# and silently breaking the GUI VPN toggle on freshly-installed services.
#
# Requires root (writes /Library/LaunchDaemons + /Library/PrivilegedHelperTools).
# Gated by NVPN_RUN_MACOS_SERVICE_E2E=1 so it doesn't run on developer
# laptops by default — runs in the GitHub Release CI on macos-14 (which
# has passwordless sudo).

set -euo pipefail

case "$(uname -s)" in
  Darwin) ;;
  *)
    echo "macOS-only e2e; skipping on $(uname -s)"
    exit 0
    ;;
esac

case "${NVPN_RUN_MACOS_SERVICE_E2E:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
  *)
    echo "Skipping macOS service e2e (set NVPN_RUN_MACOS_SERVICE_E2E=1 to run)."
    echo "It installs and uninstalls a real launchd daemon under a test"
    echo "config suffix, which mutates /Library/LaunchDaemons and"
    echo "/Library/PrivilegedHelperTools and needs root."
    exit 0
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NVPN_BIN="${NVPN_E2E_BINARY:-}"
VM_IMPORT_ONLY="${NVPN_MACOS_VM_IMPORT_ONLY:-0}"
IDLE_CPU_MAX_PERCENT="${NVPN_MACOS_DAEMON_IDLE_CPU_MAX_PERCENT:-${NVPN_IDLE_CPU_MAX_PERCENT:-2}}"
IDLE_CPU_SAMPLE_SECONDS="${NVPN_MACOS_DAEMON_IDLE_CPU_SAMPLE_SECONDS:-${NVPN_IDLE_CPU_SAMPLE_SECONDS:-60}}"
IDLE_CPU_SETTLE_SECONDS="${NVPN_MACOS_DAEMON_IDLE_CPU_SETTLE_SECONDS:-${NVPN_IDLE_CPU_SETTLE_SECONDS:-15}}"
IDLE_CPU_RESULT="${NVPN_MACOS_DAEMON_IDLE_CPU_RESULT:-$ROOT/artifacts/macos-daemon-idle-cpu.json}"

if [ -z "$NVPN_BIN" ]; then
  case "$VM_IMPORT_ONLY" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On)
      echo "VM import-only macOS service gate requires NVPN_E2E_BINARY." >&2
      exit 2
      ;;
  esac
  echo "Building nvpn (release)..."
  (cd "$ROOT" && cargo build --release -p nvpn)
  NVPN_BIN="$("$ROOT/scripts/build-output-path" --raw nvpn --release)"
fi
if [ ! -x "$NVPN_BIN" ]; then
  echo "FAIL: $NVPN_BIN missing after build"
  exit 1
fi
case "$VM_IMPORT_ONLY" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On)
    codesign --verify --strict "$NVPN_BIN"
    ;;
esac

# Use a config path with a unique suffix so the service label resolves to
# to.nostrvpn.nvpn.<suffix> and we don't touch a real user's service.
SUFFIX="e2e-$(date +%s)-$$"
TEST_DIR="$(mktemp -d /tmp/nvpn-svc-e2e.XXXXXX)"
install -d -m 700 "$TEST_DIR/cashu"
TEST_CONFIG="$TEST_DIR/$SUFFIX.toml"
TEST_CONFIG_REAL="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$TEST_CONFIG")"
PEER_CONFIG="$TEST_DIR/$SUFFIX-peer.toml"
TEST_PORT="$((52000 + $$ % 1000))"
UNDERLAY_IFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}' || true)"
if [ -z "$UNDERLAY_IFACE" ]; then
  echo "FAIL: could not resolve the macOS runner's default underlay interface" >&2
  exit 1
fi
UNDERLAY_IP="$(ipconfig getifaddr "$UNDERLAY_IFACE" 2>/dev/null || true)"
if [ -z "$UNDERLAY_IP" ]; then
  echo "FAIL: could not resolve the macOS runner's default underlay IPv4 address" >&2
  exit 1
fi
DEFAULT_CONFIG="${NVPN_MACOS_E2E_DEFAULT_CONFIG:-$HOME/Library/Application Support/nvpn/config.toml}"
RESTORE_DEFAULT_SERVICE=0

restore_default_service() {
  local attempt restore_log="$TEST_DIR/default-service-restore.log"
  for attempt in 1 2 3 4 5; do
    if sudo -n "$NVPN_BIN" service enable --config "$DEFAULT_CONFIG" \
      >"$restore_log" 2>&1
    then
      return 0
    fi
    sleep 1
  done
  cat "$restore_log" >&2 || true
  return 1
}

cleanup() {
  echo "Cleaning up test service ($TEST_CONFIG)..."
  sudo -n "$NVPN_BIN" service uninstall --config "$TEST_CONFIG" 2>/dev/null || true
  if [[ "$RESTORE_DEFAULT_SERVICE" == "1" ]]; then
    echo "Restoring the pre-existing default service..."
    restore_default_service \
      || echo "FAIL: could not restore the default macOS service" >&2
  fi
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT

default_service_json="$("$NVPN_BIN" service status --json --skip-binary-version \
  --config "$DEFAULT_CONFIG")"
default_service_active="$(printf '%s' "$default_service_json" | python3 -c '
import json, sys
s = json.load(sys.stdin)
print("true" if s.get("installed") and not s.get("disabled") and (s.get("loaded") or s.get("running")) else "false")
')"
if [[ "$default_service_active" == "true" ]]; then
  echo "Temporarily disabling the pre-existing default service..."
  sudo -n "$NVPN_BIN" service disable --config "$DEFAULT_CONFIG" >/dev/null
  RESTORE_DEFAULT_SERVICE=1
fi

"$NVPN_BIN" init --config "$TEST_CONFIG" --force >/dev/null
"$NVPN_BIN" init --config "$PEER_CONFIG" --force >/dev/null
own_npub="$(sed -n 's/^public_key = "\([^"]*\)"/\1/p' "$TEST_CONFIG" | head -1)"
peer_npub="$(sed -n 's/^public_key = "\([^"]*\)"/\1/p' "$PEER_CONFIG" | head -1)"
test -n "$own_npub" && test -n "$peer_npub"
"$NVPN_BIN" set --config "$TEST_CONFIG" \
  --participant "$own_npub" --participant "$peer_npub" \
  --endpoint "$UNDERLAY_IP:$TEST_PORT" --listen-port "$TEST_PORT" \
  --fips-peer-endpoint "$peer_npub=$UNDERLAY_IP:$((TEST_PORT + 1))" \
  --fips-advertise-endpoint true \
  --fips-nostr-discovery-enabled false --fips-bootstrap-enabled false >/dev/null

echo "Installing test service..."
sudo -n "$NVPN_BIN" service install --force --config "$TEST_CONFIG" >/dev/null

# Give launchd a moment to actually spawn the daemon.
sleep 3

runtime_json="$("$NVPN_BIN" status --json --discover-secs 0 --config "$TEST_CONFIG")"
DETECTED_RUNNING="$(printf '%s' "$runtime_json" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin).get("daemon",{}); print(str(d.get("running")).lower())')"

if [ "$DETECTED_RUNNING" != "true" ]; then
  echo "FAIL: nvpn status reports daemon.running=$DETECTED_RUNNING after"
  echo "      nvpn service install. The launchd daemon should be visible."
  echo "Service status:"
  "$NVPN_BIN" service status --config "$TEST_CONFIG" || true
  service_json="$("$NVPN_BIN" service status --json --skip-binary-version \
    --config "$TEST_CONFIG" 2>/dev/null || true)"
  service_pid="$(printf '%s' "$service_json" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("pid") or "")' \
    2>/dev/null || true)"
  service_label="$(printf '%s' "$service_json" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("label") or "")' \
    2>/dev/null || true)"
  if [[ -n "$service_label" ]]; then
    echo "launchctl service details:"
    launchctl print "system/$service_label" || true
  fi
  if [[ -n "$service_pid" ]]; then
    echo "Service process:"
    ps -ww -p "$service_pid" -o pid=,stat=,command= || true
  fi
  if [[ -f "$TEST_DIR/daemon.log" ]]; then
    echo "Daemon log:"
    tail -n 100 "$TEST_DIR/daemon.log" || true
  fi
  exit 1
fi
printf '%s' "$runtime_json" | python3 -c '
import json, sys
state = json.load(sys.stdin).get("daemon", {}).get("state", {})
if state.get("vpn_active") is not True:
    raise SystemExit("FAIL: isolated macOS daemon did not activate its VPN fixture")
'

service_json="$("$NVPN_BIN" service status --json --skip-binary-version --config "$TEST_CONFIG")"
daemon_pid="$(printf '%s' "$service_json" | python3 -c '
import json, sys
s = json.load(sys.stdin)
p = s.get("pid")
ok = s.get("supported") and s.get("installed") and s.get("loaded") and s.get("running") and isinstance(p, int) and p > 1
print(p if ok else "")
')"
daemon_binary="$(printf '%s' "$service_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("binary_path") or "")')"
daemon_command="$(ps -ww -p "$daemon_pid" -o command= 2>/dev/null || true)"
case "$daemon_command" in
  "$daemon_binary daemon --service --config $TEST_CONFIG_REAL"*) ;;
  *)
    echo "FAIL: service PID no longer matches the isolated nvpn daemon" >&2
    echo "expected prefix: $daemon_binary daemon --service --config $TEST_CONFIG_REAL" >&2
    echo "observed: $daemon_command" >&2
    exit 1
    ;;
esac

duplicate_log="$TEST_DIR/duplicate-daemon.log"
if "$NVPN_BIN" daemon --service --config "$TEST_CONFIG" >"$duplicate_log" 2>&1; then
  echo "FAIL: a second daemon started for the same config" >&2
  exit 1
fi
grep -Fq "daemon already running" "$duplicate_log" \
  || {
    echo "FAIL: duplicate daemon attempt did not report the instance lock" >&2
    cat "$duplicate_log" >&2
    exit 1
  }
daemon_process_count="$(ps -axo command= \
  | grep -F "$daemon_binary daemon --service --config $TEST_CONFIG_REAL" \
  | grep -Fvc grep \
  || true)"
if [[ "$daemon_process_count" != "1" ]]; then
  echo "FAIL: expected one isolated nvpn daemon, found $daemon_process_count" >&2
  exit 1
fi

"$ROOT/scripts/idle-cpu-gate.py" host-pid \
  --pid "$daemon_pid" \
  --label "macOS nvpn daemon" \
  --artifact "$IDLE_CPU_RESULT" \
  --max-percent "$IDLE_CPU_MAX_PERCENT" \
  --sample-seconds "$IDLE_CPU_SAMPLE_SECONDS" \
  --settle-seconds "$IDLE_CPU_SETTLE_SECONDS"

echo "Pausing..."
"$NVPN_BIN" pause --config "$TEST_CONFIG"
echo "Resuming..."
"$NVPN_BIN" resume --config "$TEST_CONFIG"

echo "MACOS_SERVICE_E2E_OK"
echo "service install -> daemon detected -> pause/resume both succeeded"
