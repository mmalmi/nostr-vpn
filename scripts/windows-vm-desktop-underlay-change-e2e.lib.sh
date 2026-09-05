#!/usr/bin/env bash
# Shared transport/guest/peer helpers for the Windows dual-NIC gate.
# This file is sourced after the orchestrator initializes its run-scoped state.

fail() {
  echo "Windows underlay network-change e2e failed: $*" >&2
  exit 1
}
validate_simple_value() {
  local label="$1"
  local value="$2"
  if [[ -z "$value" || "$value" =~ [[:space:]\'\"\;\&\|\`\\] ]]; then
    fail "$label contains unsupported shell characters"
  fi
}

for pair in \
  "hypervisor SSH:$HYPERVISOR_SSH" \
  "VM name:$VM_NAME" \
  "Windows SSH:$WINDOWS_SSH" \
  "network ID:$NETWORK_ID"
do
  validate_simple_value "${pair%%:*}" "${pair#*:}"
done

for command in git ssh scp iconv base64 jq awk; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "required command is missing: $command"
done

WINDOWS_UNDERLAY_SSH_OPTIONS=(
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ConnectionAttempts=1
  -o ControlMaster=no
  -o ControlPersist=no
  -o ControlPath=none
)

ps_quote() {
  local value="${1//\'/\'\'}"
  printf "'%s'" "$value"
}

primary_ssh_command() {
  local channel_timeout="${1:-}"
  WINDOWS_PRIMARY_SSH=(
    ssh
    "${WINDOWS_UNDERLAY_SSH_OPTIONS[@]}"
  )
  if [[ -n "$PRIMARY_PROXY" ]]; then
    WINDOWS_PRIMARY_SSH+=(-o "ProxyCommand=$PRIMARY_PROXY")
  elif [[ -n "$WINDOWS_JUMP" ]]; then
    WINDOWS_PRIMARY_SSH+=(
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPersist=no -o ControlPath=none -W %h:%p $WINDOWS_JUMP"
    )
  fi
  if [[ -n "$channel_timeout" ]]; then
    WINDOWS_PRIMARY_SSH+=(-o "ChannelTimeout=session=${channel_timeout}s")
  fi
  WINDOWS_PRIMARY_SSH+=("$WINDOWS_SSH")
}

secondary_ssh_command() {
  local channel_timeout="${1:-}"
  WINDOWS_SECONDARY_SSH=(
    ssh
    "${WINDOWS_UNDERLAY_SSH_OPTIONS[@]}"
    -o "ProxyCommand=$SECONDARY_PROXY"
  )
  if [[ -n "$channel_timeout" ]]; then
    WINDOWS_SECONDARY_SSH+=(-o "ChannelTimeout=session=${channel_timeout}s")
  fi
  WINDOWS_SECONDARY_SSH+=("$WINDOWS_SSH")
}

run_ps_with() {
  local transport="$1"
  local script="$2"
  local channel_timeout="${3:-}"
  local encoded
  encoded="$(printf '%s' "$script" | iconv -t UTF-16LE | base64 | tr -d '\n')"
  case "$transport" in
    primary)
      primary_ssh_command "$channel_timeout"
      "${WINDOWS_PRIMARY_SSH[@]}" \
        powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
          -EncodedCommand "$encoded"
      ;;
    secondary)
      secondary_ssh_command "$channel_timeout"
      "${WINDOWS_SECONDARY_SSH[@]}" \
        powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
          -EncodedCommand "$encoded"
      ;;
    *)
      fail "internal error: unknown Windows transport $transport"
      ;;
  esac
}

run_ps_primary() {
  run_ps_with primary "$1"
}

run_ps_secondary() {
  run_ps_with secondary "$1"
}

run_ps_secondary_bounded() {
  run_ps_with secondary "$1" 5
}

guest_marker_exists() {
  local name="$1"
  run_ps_secondary_bounded "if (Test-Path -LiteralPath $(ps_quote "$GUEST_STATE_DIR\\$name")) { exit 0 } else { exit 1 }" \
    >/dev/null 2>&1
}

wait_for_guest_marker() {
  local name="$1"
  local timeout_secs="${2:-120}"
  local started="$SECONDS"
  while ((SECONDS - started < timeout_secs)); do
    if guest_marker_exists "$name"; then
      return 0
    fi
    if [[ -n "$WINDOWS_RUN_PID" ]] && ! kill -0 "$WINDOWS_RUN_PID" 2>/dev/null; then
      wait "$WINDOWS_RUN_PID" || true
      tail -n 160 "$ARTIFACT_DIR/windows-run.log" >&2 || true
      fail "Windows guest runner exited before $name"
    fi
    sleep 0.1
  done
  tail -n 160 "$ARTIFACT_DIR/windows-run.log" >&2 || true
  fail "timed out waiting for Windows guest marker $name"
}

signal_guest() {
  local name="$1"
  run_ps_secondary \
    "[IO.File]::WriteAllText($(ps_quote "$GUEST_STATE_DIR\\$name"), 'go', [Text.UTF8Encoding]::new(\$false))" \
    >/dev/null
}

peer_command() {
  local action="$1"
  shift
  local -a peer_env
  peer_env=(
    "NVPN_UNDERLAY_PEER_BINARY=$HYPERVISOR_BINARY" \
    "NVPN_UNDERLAY_PEER_STATE_DIR=$PEER_STATE_DIR" \
    "NVPN_UNDERLAY_NETWORK_ID=$NETWORK_ID" \
    "NVPN_UNDERLAY_PEER_TUN_IFACE=$PEER_TUN_IFACE" \
    "NVPN_UNDERLAY_PEER_LISTEN_PORT=$PEER_LISTEN_PORT" \
    "NVPN_UNDERLAY_FIXTURE_DNS_NAME=$FIXTURE_DNS_NAME" \
    "NVPN_UNDERLAY_DNS_COUNTER_CHAIN=$COUNTER_CHAIN" \
    "NVPN_UNDERLAY_PEER_NETNS=$PEER_NETNS" \
    "NVPN_UNDERLAY_PEER_HOST_VETH=$PEER_HOST_VETH" \
    "NVPN_UNDERLAY_PEER_NS_VETH=$PEER_NS_VETH" \
    "NVPN_UNDERLAY_PEER_HOST_ADDRESS=$PEER_NAMESPACE_HOST_ADDRESS" \
    "NVPN_UNDERLAY_PEER_ADDRESS=$PEER_ENDPOINT_HOST" \
    "NVPN_UNDERLAY_PEER_PREFIX=$PEER_NAMESPACE_PREFIX" \
    "NVPN_UNDERLAY_PEER_UPLINK=$HYPERVISOR_UPLINK" \
    "NVPN_UNDERLAY_PEER_FORWARD_CHAIN=$PEER_FORWARD_CHAIN" \
    "NVPN_UNDERLAY_PEER_NAT_CHAIN=$PEER_NAT_CHAIN" \
    "NVPN_UNDERLAY_TARGET_PRIMARY_ADDRESS=$PRIMARY_ADDRESS" \
    "NVPN_UNDERLAY_TARGET_SECONDARY_ADDRESS=$SECONDARY_ADDRESS" \
    "NVPN_UNDERLAY_TARGET_LISTEN_PORT=$TARGET_LISTEN_PORT" \
    "NVPN_UNDERLAY_WG_LISTEN_PORT=$WG_LISTEN_PORT" \
    "NVPN_UNDERLAY_WG_PEER_IFACE=$WG_PEER_IFACE" \
    "NVPN_UNDERLAY_WG_CLIENT_ADDRESS=$WG_CLIENT_ADDRESS" \
    "NVPN_UNDERLAY_WG_SERVER_ADDRESS=$WG_SERVER_ADDRESS" \
    "NVPN_UNDERLAY_EXPECTED_FIPS_REV=$EXPECTED_FIPS_REV"
  )
  case "$action" in
    namespace-setup|namespace-cleanup|namespace-audit)
      ssh "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" "$HYPERVISOR_SSH" \
        sudo -n env "${peer_env[@]}" "$@" \
        "$DESKTOP_UNDERLAY_HOST_PEER_RUNNER" "$action"
      ;;
    *)
      ssh "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" "$HYPERVISOR_SSH" \
        sudo -n ip netns exec "$PEER_NETNS" env "${peer_env[@]}" "$@" \
        "$DESKTOP_UNDERLAY_HOST_PEER_RUNNER" "$action"
      ;;
  esac
}
