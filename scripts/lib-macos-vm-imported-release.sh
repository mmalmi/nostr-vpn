#!/usr/bin/env bash

_MACOS_VM_IMPORTED_RELEASE_LIB_DIR="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"
# shellcheck disable=SC1091
source "$_MACOS_VM_IMPORTED_RELEASE_LIB_DIR/lib-macos-vm-identity.sh"
unset _MACOS_VM_IMPORTED_RELEASE_LIB_DIR

macos_vm_imported_release_bool() {
  case "${1:-}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
    *) return 1 ;;
  esac
}

macos_vm_prepare_or_verify_imported_release() {
  local root="$1"
  local ssh_host="$2"
  local action="prepare-only"
  local skip_sync="${NVPN_MACOS_SKIP_GIT_SYNC:-0}"

  macos_vm_require_isolated_target "$ssh_host"

  if macos_vm_imported_release_bool \
    "${NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY:-0}"
  then
    action="verify-only"
    skip_sync=1
  fi

  NVPN_MACOS_RELEASE_ARTIFACT_ACTION="$action" \
    NVPN_MACOS_SKIP_GIT_SYNC="$skip_sync" \
    "$root/scripts/macos-vm-release-mobile-join-e2e.sh" "$ssh_host"
  export NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY=1
}

macos_vm_imported_release_package() {
  local guest_repo="$1"
  local artifact_dir="${NVPN_MACOS_RELEASE_JOIN_ARTIFACT_DIR:-artifacts/macos-release-mobile-join}"
  if [[ "$artifact_dir" == /* ]]; then
    printf '%s/imported\n' "$artifact_dir"
  elif [[ "$guest_repo" == /* ]]; then
    printf '%s/%s/imported\n' "$guest_repo" "$artifact_dir"
  else
    # Every caller changes into GUEST_REPO before invoking a gate.
    printf '%s/imported\n' "$artifact_dir"
  fi
}
