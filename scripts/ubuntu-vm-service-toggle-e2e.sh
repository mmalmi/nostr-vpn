#!/usr/bin/env bash
# Import the native candidate, exercise the real PolicyKit UI, and restore the
# isolated VM's pre-existing service registration exactly.
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
export NVPN_UBUNTU_IMPORT_EVIDENCE_DIR="$ROOT/artifacts/ubuntu-vm-import/service-toggle${RUN_ID:+-$RUN_ID}"

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

backup="$(mktemp)"
had_unit=0
was_active=0
was_enabled=0
unit_mode=
unit_uid=
unit_gid=
if [[ -f /etc/systemd/system/nvpn.service ]]; then
  sudo -n cat /etc/systemd/system/nvpn.service >"$backup"
  unit_mode="$(stat -c %a /etc/systemd/system/nvpn.service)"
  unit_uid="$(stat -c %u /etc/systemd/system/nvpn.service)"
  unit_gid="$(stat -c %g /etc/systemd/system/nvpn.service)"
  had_unit=1
  systemctl is-active --quiet nvpn.service && was_active=1 || true
  systemctl is-enabled --quiet nvpn.service && was_enabled=1 || true
fi
restore_service() {
  local status="$?"
  local restore_status=0 current_enabled=0 current_active=0
  trap - EXIT
  set +e
  if [[ "$had_unit" == 1 ]]; then
    sudo -n cp "$backup" /etc/systemd/system/nvpn.service
    sudo -n chown "$unit_uid:$unit_gid" /etc/systemd/system/nvpn.service
    sudo -n chmod "$unit_mode" /etc/systemd/system/nvpn.service
    sudo -n systemctl daemon-reload
    [[ "$was_enabled" == 1 ]] && sudo -n systemctl enable nvpn.service >/dev/null
    [[ "$was_active" == 1 ]] && sudo -n systemctl start nvpn.service
    sudo -n cmp -s "$backup" /etc/systemd/system/nvpn.service || restore_status=1
    [[ "$(stat -c %a /etc/systemd/system/nvpn.service)" == "$unit_mode" ]] \
      || restore_status=1
    [[ "$(stat -c %u /etc/systemd/system/nvpn.service)" == "$unit_uid" ]] \
      || restore_status=1
    [[ "$(stat -c %g /etc/systemd/system/nvpn.service)" == "$unit_gid" ]] \
      || restore_status=1
    systemctl is-enabled --quiet nvpn.service && current_enabled=1
    systemctl is-active --quiet nvpn.service && current_active=1
    [[ "$current_enabled" == "$was_enabled" ]] || restore_status=1
    [[ "$current_active" == "$was_active" ]] || restore_status=1
  else
    sudo -n systemctl stop nvpn.service >/dev/null 2>&1 || true
    sudo -n systemctl disable nvpn.service >/dev/null 2>&1 || true
    sudo -n rm -f /etc/systemd/system/nvpn.service
    sudo -n systemctl daemon-reload
    systemctl show nvpn.service --property=LoadState --value 2>/dev/null \
      | grep -qx not-found || restore_status=1
  fi
  rm -f "$backup"
  if [[ "$restore_status" != 0 ]]; then
    echo "Failed to restore the pre-gate nvpn.service state." >&2
    exit "$restore_status"
  fi
  exit "$status"
}
trap restore_service EXIT

if [[ "$had_unit" == 1 ]]; then
  sudo -n systemctl stop nvpn.service
  sudo -n systemctl disable nvpn.service >/dev/null 2>&1 || true
  sudo -n rm -f /etc/systemd/system/nvpn.service
  sudo -n systemctl daemon-reload
fi
env \
  ARTIFACT_ROOT="$repo/artifacts/linux-service-toggle-real${run_id:+-$run_id}" \
  NVPN_LINUX_APP_PATH="$app" \
  NVPN_LINUX_NVPN_PATH="$cli" \
  NVPN_LINUX_FIXTURE_PATH="$fixture" \
  ./scripts/e2e-linux-service-toggle-real.sh
GUEST

echo "UBUNTU_VM_SERVICE_TOGGLE_E2E_OK"
