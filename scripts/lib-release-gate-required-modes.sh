#!/usr/bin/env bash

# Ordinary developer release-gate runs may auto-detect expensive physical and
# isolated-VM fixtures. A complete release run may not: convert every real
# network auto mode to required, and reject explicit attempts to disable one.

release_gate_require_real_network_mode() {
  local name="$1"
  local value="${!name:-auto}"
  case "$value" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Complete release gate cannot disable $name." >&2
      return 1
      ;;
    auto|AUTO|Auto|"")
      printf -v "$name" '%s' required
      export "$name"
      ;;
  esac
}

release_gate_enforce_complete_real_network_modes() {
  case "${NVPN_RELEASE_GATE_REQUIRE_COMPLETE:-0}" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off|"")
      return 0
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
    *)
      echo "NVPN_RELEASE_GATE_REQUIRE_COMPLETE must be a boolean." >&2
      return 2
      ;;
  esac

  local name
  for name in \
    NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E \
    NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E \
    NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E \
    NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E \
    NVPN_RELEASE_GATE_MOBILE_WG_EXIT_E2E \
    NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E
  do
    release_gate_require_real_network_mode "$name" || return
  done
}

release_gate_require_complete_fixture_inputs() {
  case "${NVPN_RELEASE_GATE_REQUIRE_COMPLETE:-0}" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off|"") return 0 ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
    *)
      echo "NVPN_RELEASE_GATE_REQUIRE_COMPLETE must be a boolean." >&2
      return 2
      ;;
  esac

  local provider_config="${NVPN_WINDOWS_WG_EXIT_CONFIG_FILE:-${NVPN_WG_EXIT_CONFIG_FILE:-}}"
  if [[ -n "$provider_config" ]]; then
    [[ -r "$provider_config" ]] || {
      echo "Complete release gate Windows WireGuard config is unreadable." >&2
      return 1
    }
  elif [[ -z "${NVPN_WINDOWS_WG_FIXTURE_HOST_IP:-}" ]]; then
    echo "Complete release gate requires a reachable Windows WireGuard fixture address or an explicit provider config." >&2
    return 1
  elif [[ -n "${NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST:-}" \
    && "${NVPN_MOBILE_WG_EXIT_REMOTE_MODE:-native}" != native ]]
  then
    echo "Complete release gate Windows WireGuard fixture must use remote native mode." >&2
    return 1
  elif [[ -z "${NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST:-}" ]] \
    && ! command -v docker >/dev/null 2>&1
  then
    echo "Complete release gate local WireGuard fixture requires Docker." >&2
    return 1
  fi

  [[ -n "${NVPN_MOBILE_WG_EXIT_HOST_IP:-}" ]] || {
    echo "Complete release gate requires NVPN_MOBILE_WG_EXIT_HOST_IP for physical mobile network gates." >&2
    return 1
  }
  local android_signer
  android_signer="$(
    printf '%s' "${NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256:-}" \
      | tr -d ':[:space:]' \
      | tr '[:upper:]' '[:lower:]'
  )"
  [[ "$android_signer" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Complete release gate requires an exact Android signer certificate SHA-256 pin." >&2
    return 1
  }
  [[ -n "${NVPN_MACOS_WG_FIXTURE_HOST_IP:-}" ]] || {
    echo "Complete release gate requires NVPN_MACOS_WG_FIXTURE_HOST_IP for the local macOS WireGuard exit fixture." >&2
    return 1
  }
  [[ -n "${NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH:-}" ]] || {
    echo "Complete release gate requires NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH for desktop underlay gates." >&2
    return 1
  }
  [[ -n "${NVPN_WINDOWS_UNDERLAY_VM_NAME:-${NVPN_WINDOWS_VM_NAME:-}}" ]] || {
    echo "Complete release gate requires a Windows underlay VM name." >&2
    return 1
  }
  [[ -n "${NVPN_LINUX_UNDERLAY_VM_NAME:-${NVPN_UBUNTU_VM_NAME:-}}" ]] || {
    echo "Complete release gate requires a Linux underlay VM name." >&2
    return 1
  }
}
