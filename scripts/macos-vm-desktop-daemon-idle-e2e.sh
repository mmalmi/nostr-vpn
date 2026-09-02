#!/usr/bin/env bash
# Run the launchd/VPN/idle-CPU service proof only inside the disposable macOS
# VM so the release gate cannot install a daemon or routes on its host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-vm-imported-release.sh"
SSH_HOST="${NVPN_MACOS_SSH_HOST:-${1:-}}"
GUEST_SRC_ROOT="${NVPN_MACOS_GUEST_SRC_ROOT:-src}"
GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn"
REMOTE_RESULT="artifacts/macos-daemon-idle-cpu.json"
REMOTE_RESULT_SCP="$GUEST_REPO/$REMOTE_RESULT"
LOCAL_RESULT="${ARTIFACT_ROOT:-$ROOT/artifacts}/macos-daemon-idle-cpu.json"
[[ -n "$SSH_HOST" ]] || {
  echo "set NVPN_MACOS_SSH_HOST or pass the macOS VM SSH target" >&2
  exit 2
}

macos_vm_prepare_or_verify_imported_release "$ROOT" "$SSH_HOST"
package="$(macos_vm_imported_release_package "$GUEST_REPO")"
remote_env=(
  NVPN_MACOS_VM_IMPORT_ONLY=1
  "NVPN_E2E_BINARY=$package/Nostr VPN.app/Contents/Resources/nvpn"
  NVPN_RUN_MACOS_SERVICE_E2E=1
  NVPN_MACOS_DAEMON_IDLE_CPU_RESULT="$REMOTE_RESULT"
  NVPN_MACOS_DAEMON_IDLE_CPU_MAX_PERCENT="${NVPN_MACOS_DAEMON_IDLE_CPU_MAX_PERCENT:-${NVPN_IDLE_CPU_MAX_PERCENT:-2}}"
  NVPN_MACOS_DAEMON_IDLE_CPU_SAMPLE_SECONDS="${NVPN_MACOS_DAEMON_IDLE_CPU_SAMPLE_SECONDS:-${NVPN_IDLE_CPU_SAMPLE_SECONDS:-60}}"
  NVPN_MACOS_DAEMON_IDLE_CPU_SETTLE_SECONDS="${NVPN_MACOS_DAEMON_IDLE_CPU_SETTLE_SECONDS:-${NVPN_IDLE_CPU_SETTLE_SECONDS:-15}}"
)
remote_command="cd '$GUEST_REPO' && mkdir -p artifacts && env"
for assignment in "${remote_env[@]}"; do
  remote_command+=" '$assignment'"
done
remote_command+=" ./scripts/e2e-macos-service.sh"

ssh -o BatchMode=yes "$SSH_HOST" "$remote_command"
mkdir -p "$(dirname "$LOCAL_RESULT")"
scp -q "$SSH_HOST:$REMOTE_RESULT_SCP" "$LOCAL_RESULT"
echo "MACOS_VM_DAEMON_IDLE_CPU_E2E_OK"
