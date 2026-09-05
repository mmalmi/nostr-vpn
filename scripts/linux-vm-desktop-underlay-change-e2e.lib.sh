#!/usr/bin/env bash
# Shared transport/guest/peer helpers for the Linux dual-NIC gate.
# This file is sourced after the orchestrator initializes its run-scoped state.

fail() {
  echo "Linux VM underlay network-change e2e failed: $*" >&2
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
  "Linux SSH:$LINUX_SSH" \
  "network ID:$NETWORK_ID" \
  "guest source root:$GUEST_SRC_ROOT"
do
  validate_simple_value "${pair%%:*}" "${pair#*:}"
done

for command in git ssh jq awk perl; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "required command is missing: $command"
done

SSH_LIVENESS_OPTIONS=(
  -o BatchMode=yes
  -o ConnectionAttempts=1
  -o ConnectTimeout=10
  -o ControlMaster=no
  -o ControlPersist=no
  -o ControlPath=none
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=2
)

hypervisor_ssh_command() {
  LINUX_HYPERVISOR_SSH=(
    ssh
    "${SSH_LIVENESS_OPTIONS[@]}"
    "$HYPERVISOR_SSH"
  )
}

run_hypervisor() {
  hypervisor_ssh_command
  "${LINUX_HYPERVISOR_SSH[@]}" "$@"
}

run_hypervisor_bounded() {
  local timeout_secs="$1"
  shift
  hypervisor_ssh_command
  perl -e '
    my $seconds = shift @ARGV;
    alarm $seconds;
    exec @ARGV;
    die "exec failed: $!\n";
  ' "$timeout_secs" "${LINUX_HYPERVISOR_SSH[@]}" "$@"
}

primary_ssh_command() {
  LINUX_PRIMARY_SSH=(ssh "${SSH_LIVENESS_OPTIONS[@]}")
  if [[ -n "$PRIMARY_PROXY" ]]; then
    LINUX_PRIMARY_SSH+=(-o "ProxyCommand=$PRIMARY_PROXY")
  elif [[ -n "$LINUX_JUMP" ]]; then
    LINUX_PRIMARY_SSH+=(
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPersist=no -o ControlPath=none -W %h:%p $LINUX_JUMP"
    )
  fi
  LINUX_PRIMARY_SSH+=("$LINUX_SSH")
}

secondary_ssh_command() {
  LINUX_SECONDARY_SSH=(
    ssh
    "${SSH_LIVENESS_OPTIONS[@]}"
    -o "ProxyCommand=$SECONDARY_PROXY"
    "$LINUX_SSH"
  )
}

run_primary() {
  primary_ssh_command
  "${LINUX_PRIMARY_SSH[@]}" "$@"
}

run_secondary() {
  secondary_ssh_command
  "${LINUX_SECONDARY_SSH[@]}" "$@"
}

run_secondary_bounded() {
  local timeout_secs="$1"
  shift
  secondary_ssh_command
  perl -e '
    my $seconds = shift @ARGV;
    alarm $seconds;
    exec @ARGV;
    die "exec failed: $!\n";
  ' "$timeout_secs" "${LINUX_SECONDARY_SSH[@]}" "$@"
}

linux_guest_env() {
  LINUX_GUEST_ENV=(
    "NVPN_UNDERLAY_BINARY=$GUEST_BINARY" \
    "NVPN_UNDERLAY_STATE_DIR=$GUEST_STATE_DIR" \
    "NVPN_UNDERLAY_PRIMARY_MAC=$PRIMARY_MAC" \
    "NVPN_UNDERLAY_SECONDARY_MAC=$SECONDARY_MAC" \
    "NVPN_UNDERLAY_SECONDARY_ADDRESS=$SECONDARY_ADDRESS" \
    "NVPN_UNDERLAY_SECONDARY_PREFIX=$SECONDARY_PREFIX" \
    "NVPN_UNDERLAY_SECONDARY_GATEWAY=$SECONDARY_GATEWAY" \
    "NVPN_UNDERLAY_NETWORK_ID=$NETWORK_ID" \
    "NVPN_UNDERLAY_FIXTURE_DNS_NAME=$FIXTURE_DNS_NAME" \
    "NVPN_UNDERLAY_PROBE_URL=$PROBE_URL" \
    "NVPN_UNDERLAY_TUN_IFACE=$TARGET_TUN_IFACE" \
    "NVPN_UNDERLAY_RECOVERY_DEADLINE_MS=$RECOVERY_DEADLINE_MS" \
    "NVPN_UNDERLAY_EXPECTED_FIPS_REV=$EXPECTED_FIPS_REV"
  )
}

run_guest_primary() {
  local action="$1"
  shift
  linux_guest_env
  primary_ssh_command
  "${LINUX_PRIMARY_SSH[@]}" sudo -n env "${LINUX_GUEST_ENV[@]}" \
    "$@" "$GUEST_RUNNER" "$action"
}

start_guest_secondary_unit() {
  local action="$1"
  shift
  [[ -n "$LINUX_RUN_UNIT" && "$GUEST_REPO" == /* ]] \
    || fail "Linux detached guest runner is not initialized"
  linux_guest_env
  secondary_ssh_command
  "${LINUX_SECONDARY_SSH[@]}" sudo -n systemd-run \
    "--unit=$LINUX_RUN_UNIT" --collect --quiet \
    --property=Type=exec --property=RemainAfterExit=yes \
    --property=RuntimeMaxSec=600 --property=TimeoutStopSec=15 \
    --property=KillMode=mixed \
    "--property=StandardOutput=append:$GUEST_STATE_DIR/runner.stdout.log" \
    "--property=StandardError=append:$GUEST_STATE_DIR/runner.stderr.log" \
    /usr/bin/env "${LINUX_GUEST_ENV[@]}" \
    "$@" "$GUEST_RUNNER" "$action"
}

wait_for_guest_runner_success() {
  # The guest's Direct restoration loop may consume its full 30-second
  # deadline. Leave enough time for it to write the receipt and for the
  # systemd state transition to become visible over SSH.
  local deadline="$((SECONDS + 60))"
  local state
  while ((SECONDS < deadline)); do
    state="$(run_primary sudo -n systemctl show "$LINUX_RUN_UNIT" \
      --property=ActiveState --property=SubState \
      --property=Result --property=ExecMainStatus 2>/dev/null)" || {
      sleep 0.1
      continue
    }
    if grep -Fqx 'ActiveState=active' <<<"$state" \
      && grep -Fqx 'SubState=exited' <<<"$state" \
      && grep -Fqx 'Result=success' <<<"$state" \
      && grep -Fqx 'ExecMainStatus=0' <<<"$state"
    then
      printf '%s\n' "$state"
      return 0
    fi
    grep -Eq '^ActiveState=(activating|active)$' <<<"$state" || break
    sleep 0.1
  done
  printf '%s\n' "${state:-unit state unavailable}" >&2
  fail "detached Linux guest runner did not exit successfully"
}

stop_guest_runner_unit() {
  [[ -n "$LINUX_RUN_UNIT" ]] || return 0
  run_primary sudo -n systemctl stop "$LINUX_RUN_UNIT"
  LINUX_RUN_UNIT=""
}

guest_marker_exists() {
  run_secondary_bounded 8 \
    sudo -n test -e "$GUEST_STATE_DIR/$1" >/dev/null 2>&1
}

wait_for_guest_marker() {
  local name="$1"
  local timeout_secs="${2:-30}"
  local started="$SECONDS"
  local state
  while ((SECONDS - started < timeout_secs)); do
    if guest_marker_exists "$name"; then
      return 0
    fi
    state="$(run_secondary_bounded 8 sudo -n systemctl show "$LINUX_RUN_UNIT" \
      --property=ActiveState --value 2>/dev/null)" || state=""
    [[ -z "$state" || "$state" == "active" ]] \
      || fail "Linux guest runner exited before $name"
    sleep 0.1
  done
  fail "timed out waiting for Linux guest marker $name"
}

signal_guest() {
  run_secondary sudo -n touch "$GUEST_STATE_DIR/$1"
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
    "NVPN_UNDERLAY_TARGET_LISTEN_PORT=$TARGET_LISTEN_PORT"
    "NVPN_UNDERLAY_WG_LISTEN_PORT=$WG_LISTEN_PORT"
    "NVPN_UNDERLAY_WG_PEER_IFACE=$WG_PEER_IFACE"
    "NVPN_UNDERLAY_WG_CLIENT_ADDRESS=$WG_CLIENT_ADDRESS"
    "NVPN_UNDERLAY_WG_SERVER_ADDRESS=$WG_SERVER_ADDRESS"
    "NVPN_UNDERLAY_EXPECTED_FIPS_REV=$EXPECTED_FIPS_REV"
  )
  case "$action" in
    namespace-setup|namespace-cleanup|namespace-audit)
      run_hypervisor_bounded 60 \
        sudo -n env "${peer_env[@]}" "$@" \
        "$DESKTOP_UNDERLAY_HOST_PEER_RUNNER" "$action"
      ;;
    *)
      run_hypervisor_bounded 60 \
        sudo -n ip netns exec "$PEER_NETNS" env "${peer_env[@]}" "$@" \
        "$DESKTOP_UNDERLAY_HOST_PEER_RUNNER" "$action"
      ;;
  esac
}
