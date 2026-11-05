#!/usr/bin/env bash
# Import and drive both shipped GTK manual-join roles on an isolated Linux VM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_HOST="${NVPN_UBUNTU_SSH_HOST:-${1:-}}"
GUEST_SRC_ROOT="${NVPN_UBUNTU_GUEST_SRC_ROOT:-src}"
GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn-release-gate"
RUN_ID="${NVPN_UBUNTU_UI_RUN_ID:-}"
[[ -z "$RUN_ID" || "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || exit 2
[[ -n "$SSH_HOST" ]] || {
  echo "set NVPN_UBUNTU_SSH_HOST or pass the Linux VM SSH target" >&2
  exit 2
}

# shellcheck disable=SC1091
source "$ROOT/scripts/lib-ubuntu-vm-imported-release.sh"
export NVPN_UBUNTU_IMPORT_EVIDENCE_DIR="$ROOT/artifacts/ubuntu-vm-import/manual-join${RUN_ID:+-$RUN_ID}"

cleanup() {
  local status="$?"
  trap - EXIT
  if ! ubuntu_vm_cleanup_imported_release_bundle; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

case "${NVPN_UBUNTU_SKIP_GIT_SYNC:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
  *) "$ROOT/scripts/ubuntu-vm-git-sync.sh" "$SSH_HOST" ;;
esac
ubuntu_vm_import_release_bundle
ubuntu_vm_import_ssh_command

"${NVPN_UBUNTU_IMPORT_SSH[@]}" bash -s -- \
  "$GUEST_REPO" \
  "$NVPN_UBUNTU_IMPORTED_APP" \
  "$NVPN_UBUNTU_IMPORTED_CLI" \
  "$NVPN_UBUNTU_IMPORTED_FIXTURE" \
  "$RUN_ID" <<'GUEST'
set -euo pipefail
repo="$1"
app="$2"
cli="$3"
fixture="$4"
run_id="${5:-}"
[[ -z "$run_id" || "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || exit 2
cd "$repo"
repo="$(pwd -P)"
artifact="$repo/artifacts/linux-manual-join-ui${run_id:+-$run_id}"
env \
  ARTIFACT_ROOT="$artifact" \
  NVPN_LINUX_UI_RUN_ID="$run_id" \
  NVPN_REPO_ROOT="$repo" \
  NVPN_LINUX_APP_PATH="$app" \
  NVPN_LINUX_NVPN_PATH="$cli" \
  NVPN_LINUX_FIXTURE_PATH="$fixture" \
  xvfb-run -a dbus-run-session -- ./linux/scripts/e2e-manual-join-ui.sh
python3 - "$artifact" <<'PY'
import json
import sys
from pathlib import Path

artifact = Path(sys.argv[1])
result = json.loads((artifact / "result.json").read_text(encoding="utf-8"))
required = {
    "ok": True,
    "phase": "ui-verified",
    "transportMode": "public-websocket",
    "ambientDiscoveryDisabled": True,
    "directPeerConfigAbsent": True,
    "adminOutboxQueuedBeforeRuntime": True,
    "adminOutboxAttemptsBeforeRuntime": 0,
    "adminOutboxLastAttemptAtBeforeRuntime": 0,
    "deliveryCompletedDuringUi": False,
}
for key, expected in required.items():
    if result.get(key) != expected:
        raise SystemExit(f"Linux manual-join result lacks {key}={expected!r}")
for name in ("joiner.png", "admin.png"):
    if not (artifact / name).is_file():
        raise SystemExit(f"Linux manual-join artifact missing: {name}")
PY
GUEST

echo "UBUNTU_VM_DESKTOP_MANUAL_JOIN_UI_E2E_OK"
