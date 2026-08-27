#!/usr/bin/env bash
# Source contract for the production-path desktop underlay gates. The actual
# packet/DNS assertions run on the real VMs; this keeps publication from
# silently replacing them with a mock, a link simulation, or an optional lane.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_GATE="$ROOT/scripts/release-gate.sh"
LOCAL_RELEASE="$ROOT/scripts/local-release.mjs"
NETWORK_EVIDENCE="$ROOT/scripts/release-network-evidence.py"
WINDOWS_HOST_ENTRY="$ROOT/scripts/windows-vm-desktop-underlay-change-e2e.sh"
WINDOWS_HOST_LIB="$ROOT/scripts/windows-vm-desktop-underlay-change-e2e.lib.sh"
WINDOWS_PEER_OBSERVER="$ROOT/scripts/desktop-underlay-peer-recovery-observer.sh"
WINDOWS_GUEST_ENTRY="$ROOT/scripts/desktop-windows-underlay-change-e2e.ps1"
WINDOWS_GUEST_LIB="$ROOT/scripts/desktop-windows-underlay-change-e2e.lib.ps1"
WINDOWS_GUEST_CRASH_LIB="$ROOT/scripts/desktop-windows-underlay-crash-recovery.lib.ps1"
WINDOWS_OWNERSHIP_HARNESS="$ROOT/scripts/test-desktop-windows-wireguard-ownership.ps1"
LINUX_HOST_ENTRY="$ROOT/scripts/linux-vm-desktop-underlay-change-e2e.sh"
LINUX_HOST_LIB="$ROOT/scripts/linux-vm-desktop-underlay-change-e2e.lib.sh"
LINUX_GUEST="$ROOT/scripts/desktop-linux-underlay-change-e2e.sh"
LINUX_CLEANUP_FAULT="$ROOT/scripts/desktop-linux-cleanup-fault-e2e.sh"
PEER="$ROOT/scripts/desktop-linux-underlay-peer-e2e.sh"
HOST_PEER_IMPORT="$ROOT/scripts/lib-desktop-underlay-host-peer.sh"
HOST_PEER_VERIFY="$ROOT/scripts/verify-host-linux-peer-artifact.py"
LISTENER_AUDIT="$ROOT/scripts/lib-desktop-linux-listener-audit.sh"
WIREGUARD_FIXTURE_LIB="$ROOT/scripts/lib-mobile-wireguard-fixture.sh"
MACOS_WIREGUARD="$ROOT/scripts/macos-vm-desktop-wireguard-exit-e2e.sh"
MACOS_NETWORK_GUEST="$ROOT/scripts/e2e-macos-release-network.sh"
MACOS_APP="$ROOT/scripts/macos-vm-desktop-app-launch-smoke.sh"
MACOS_IDLE="$ROOT/scripts/macos-vm-desktop-daemon-idle-e2e.sh"
LINUX_SYNC="$ROOT/scripts/ubuntu-vm-git-sync.sh"
WINDOWS_SYNC="$ROOT/scripts/windows-vm-git-sync.sh"
COMBINED_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-underlay-contract.XXXXXX")"
trap 'rm -rf "$COMBINED_DIR"' EXIT
WINDOWS_HOST="$COMBINED_DIR/windows-host.sh"
WINDOWS_GUEST="$COMBINED_DIR/windows-guest.ps1"
LINUX_HOST="$COMBINED_DIR/linux-host.sh"
cat "$WINDOWS_HOST_ENTRY" "$WINDOWS_HOST_LIB" "$WINDOWS_PEER_OBSERVER" \
  >"$WINDOWS_HOST"
cat "$WINDOWS_GUEST_ENTRY" "$WINDOWS_GUEST_LIB" "$WINDOWS_GUEST_CRASH_LIB" \
  >"$WINDOWS_GUEST"
cat "$LINUX_HOST_ENTRY" "$LINUX_HOST_LIB" "$WINDOWS_PEER_OBSERVER" \
  >"$LINUX_HOST"

fail() {
  echo "desktop underlay source contract failed: $*" >&2
  exit 1
}

require_tokens() {
  local file="$1" label="$2" token
  shift 2
  for token in "$@"; do
    grep -Fq -- "$token" "$file" \
      || fail "$(basename "$file") lacks $label: $token"
  done
}

reject_listener_fixture() {
  local label="$1"
  shift
  if nvpn_require_single_udp_listener "$@" >/dev/null 2>&1; then
    fail "$label passed the listener audit"
  fi
}

reject_dual_listener_fixture() {
  local label="$1"
  shift
  if nvpn_require_dual_family_udp_listeners "$@" >/dev/null 2>&1; then
    fail "$label passed the dual-family listener audit"
  fi
}

[[ -f "$LISTENER_AUDIT" ]] || fail "Linux UDP listener audit helper is missing"
source "$LISTENER_AUDIT"

for script in \
  "$WINDOWS_HOST_ENTRY" "$LINUX_HOST_ENTRY" "$LINUX_GUEST" \
  "$LINUX_CLEANUP_FAULT" "$PEER" \
  "$MACOS_WIREGUARD" "$MACOS_NETWORK_GUEST" "$MACOS_APP" "$MACOS_IDLE"
do
  [[ -x "$script" ]] || fail "$(basename "$script") is missing or not executable"
done
for helper in \
  "$WINDOWS_HOST_LIB" "$WINDOWS_GUEST_LIB" "$WINDOWS_GUEST_CRASH_LIB" \
  "$LINUX_HOST_LIB" "$WINDOWS_OWNERSHIP_HARNESS"
do
  [[ -f "$helper" ]] || fail "$(basename "$helper") is missing"
done
[[ -f "$HOST_PEER_IMPORT" ]] || fail "host-built peer importer is missing"
[[ -x "$HOST_PEER_VERIFY" ]] || fail "host-built peer verifier is missing"
[[ -f "$WINDOWS_GUEST_ENTRY" ]] || fail "Windows guest runner is missing"
require_tokens "$WINDOWS_HOST_ENTRY" "helper module" \
  'windows-vm-desktop-underlay-change-e2e.lib.sh'
require_tokens "$WINDOWS_GUEST_ENTRY" "helper module" \
  'desktop-windows-underlay-change-e2e.lib.ps1' \
  'desktop-windows-underlay-crash-recovery.lib.ps1'
require_tokens "$WINDOWS_GUEST_CRASH_LIB" "granular Direct startup-recovery evidence" \
  'best route interface' \
  'native WireGuard adapter remains' \
  'native WireGuard service remains' \
  'endpoint bypass route remains' \
  'secure DNS policy remains' \
  'paid-exit default route remains in cleanup journal' \
  'paid-exit endpoint route remains in cleanup journal' \
  'native WireGuard ownership remains in cleanup journal' \
  'secure DNS ownership remains in cleanup journal' \
  'public DNS is unavailable' \
  'verified HTTPS is unavailable'
require_tokens "$WINDOWS_HOST_ENTRY" "native WireGuard ownership regression harness" \
  'test-desktop-windows-wireguard-ownership.ps1' \
  'windows-wireguard-ownership-harness.log'
require_tokens "$WINDOWS_OWNERSHIP_HARNESS" "fail-closed owner-token fixtures" \
  'current owner-token layout' \
  'legacy flat config path' \
  'wrong owner directory' \
  'missing config' \
  'missing owner marker' \
  'mismatched owner marker' \
  'multiple journal owners' \
  'inheriting secret ACL' \
  'WINDOWS_NATIVE_WIREGUARD_OWNERSHIP_HARNESS_OK'
require_tokens "$LINUX_HOST_ENTRY" "helper module" \
  'linux-vm-desktop-underlay-change-e2e.lib.sh'
require_tokens "$LINUX_HOST_ENTRY" "artifact-bound product/harness separation" \
  'RELEASE_APP_ROOT="${NVPN_RELEASE_APP_REPO_PATH:-$ROOT}"' \
  'app_sha="$(git -C "$RELEASE_APP_ROOT" rev-parse HEAD)"' \
  'harness_sha="$(git -C "$ROOT" rev-parse HEAD)"' \
  'NVPN_UBUNTU_LOCAL_REPO_PATH="$RELEASE_APP_ROOT"' \
  'GUEST_RUNNER="$GUEST_IMPORT_DIR/desktop-linux-underlay-change-e2e.sh"' \
  'harnessRunnerSha256=%s'
require_tokens "$LINUX_HOST_LIB" "imported versioned guest harness" \
  '"$@" "$GUEST_RUNNER" "$action"'
require_tokens "$LINUX_CLEANUP_FAULT" "successful interface lookup status" \
  'basename "$(dirname "$path")"' \
  'return 0' \
  'return 1'
require_tokens "$LINUX_GUEST" "short owned netlink probe runtime" \
  'local probe_dir="/tmp/nvpn-pnm-$$-${RANDOM}"' \
  'local join_socket_probe="$probe_dir/.nvpn-runtime/join-0000000000000000.sock"' \
  '((${#join_socket_probe} <= 107))' \
  '[[ ! -e "$probe_dir" ]]' \
  '[[ -d "$probe_dir" && -O "$probe_dir" && ! -L "$probe_dir" ]]'
require_tokens "$LINUX_SYNC" "isolated exact-source sync support" \
  'NVPN_UBUNTU_LOCAL_REPO_PATH' \
  'NVPN_UBUNTU_SSH_JUMP' \
  'NVPN_UBUNTU_SSH_PROXY_COMMAND' \
  'NVPN_UBUNTU_GUEST_REPO_NAME' \
  'NVPN_UBUNTU_REPO_LABEL' \
  'NVPN_UBUNTU_GIT_SYNC_EXACT_COMMIT'
require_tokens "$WINDOWS_SYNC" "isolated exact-FIPS sync support" \
  'FIPS_REPO="${NVPN_WINDOWS_FIPS_REPO_PATH:-${NVPN_FIPS_REPO_PATH:-$SRC_ROOT/fips}}"' \
  'NVPN_WINDOWS_GUEST_FIPS_REPO_PATH' \
  'NVPN_WINDOWS_FIPS_GIT_BARE_PATH' \
  'NVPN_WINDOWS_GIT_SYNC_EXACT_APP_COMMIT'
require_tokens "$RELEASE_GATE" "exact release-FIPS Windows lane binding" \
  'NVPN_WINDOWS_FIPS_REPO_PATH="$release_fips_path"' \
  './scripts/windows-vm-git-sync.sh "$host"'

listener_fixture_device="nvln0"
listener_fixture_port="45820"
listener_fixture_pid="4242"
listener_fixture_row='UNCONN 0 0 0.0.0.0%nvln0:45820 0.0.0.0:* users:(("nvpn",pid=4242,fd=11))'
validated_listener="$(
  nvpn_require_single_udp_listener \
    "$listener_fixture_row" \
    "$listener_fixture_device" \
    "$listener_fixture_port" \
    "$listener_fixture_pid"
)" || fail "valid exact-device daemon listener fixture was rejected"
[[ "$validated_listener" == "$listener_fixture_row" ]] \
  || fail "listener helper did not return the exact validated row"
ipv6_listener_fixture_row='UNCONN 0 0 [::]%nvln0:45820 [::]:* users:(("nvpn",pid=4242,fd=12))'
dual_family_listener_rows="$listener_fixture_row"$'\n'"$ipv6_listener_fixture_row"
validated_dual_listeners="$(
  nvpn_require_dual_family_udp_listeners \
    "$dual_family_listener_rows" \
    "$listener_fixture_device" \
    "$listener_fixture_port" \
    "$listener_fixture_pid"
)" || fail "valid same-port IPv4/IPv6 listener pair was rejected"
[[ "$validated_dual_listeners" == "$dual_family_listener_rows" ]] \
  || fail "listener helper did not return the exact validated dual-family rows"
validated_legacy_ipv6_listener="$(
  nvpn_require_single_udp_listener \
    "$ipv6_listener_fixture_row" \
    "$listener_fixture_device" \
    "$listener_fixture_port" \
    "$listener_fixture_pid"
)" || fail "valid legacy single IPv6 listener fixture was rejected"
[[ "$validated_legacy_ipv6_listener" == "$ipv6_listener_fixture_row" ]] \
  || fail "listener helper did not return the exact legacy IPv6 row"
reuseport_compatible_rows="$listener_fixture_row"$'\n''UNCONN 0 0 0.0.0.0%nvln0:45820 0.0.0.0:* users:(("nvpn",pid=4242,fd=12))'
reject_listener_fixture "duplicate SO_REUSEPORT-compatible rows" \
  "$reuseport_compatible_rows" "$listener_fixture_device" \
  "$listener_fixture_port" "$listener_fixture_pid"
reject_dual_listener_fixture "duplicate IPv4 rows masquerading as dual-family" \
  "$reuseport_compatible_rows" "$listener_fixture_device" \
  "$listener_fixture_port" "$listener_fixture_pid"
reject_listener_fixture "listener on the wrong device" \
  "$listener_fixture_row" wrong0 "$listener_fixture_port" "$listener_fixture_pid"
reject_listener_fixture "listener owned by a PID prefix" \
  "$listener_fixture_row" "$listener_fixture_device" "$listener_fixture_port" 424
shared_listener_row='UNCONN 0 0 0.0.0.0%nvln0:45820 0.0.0.0:* users:(("other",pid=9999,fd=3),("nvpn",pid=4242,fd=11))'
reject_listener_fixture "listener row shared with a foreign PID" \
  "$shared_listener_row" "$listener_fixture_device" \
  "$listener_fixture_port" "$listener_fixture_pid"
dual_family_foreign_owner_rows="$listener_fixture_row"$'\n''UNCONN 0 0 [::]%nvln0:45820 [::]:* users:(("other",pid=9999,fd=12))'
reject_dual_listener_fixture "dual-family row owned by a foreign PID" \
  "$dual_family_foreign_owner_rows" "$listener_fixture_device" \
  "$listener_fixture_port" "$listener_fixture_pid"
dual_family_wrong_interface_rows="$listener_fixture_row"$'\n''UNCONN 0 0 [::]%wrong0:45820 [::]:* users:(("nvpn",pid=4242,fd=12))'
reject_dual_listener_fixture "dual-family row on the wrong device" \
  "$dual_family_wrong_interface_rows" "$listener_fixture_device" \
  "$listener_fixture_port" "$listener_fixture_pid"
three_listener_rows="$dual_family_listener_rows"$'\n'"$listener_fixture_row"
reject_dual_listener_fixture "extra third listener row" \
  "$three_listener_rows" "$listener_fixture_device" \
  "$listener_fixture_port" "$listener_fixture_pid"
listener_audit_body="$(sed -n '/^listener_audit() {$/,/^}$/p' "$PEER")"
grep -Fq 'nvpn_require_dual_family_udp_listeners' <<<"$listener_audit_body" \
  || fail "peer listener audit does not require the exact IPv4/IPv6 pair"
if grep -Fq 'nvpn_require_single_udp_listener' <<<"$listener_audit_body"; then
  fail "peer listener audit still accepts a single UDP listener"
fi
require_tokens "$PEER" "listener ownership integration" \
  'lib-desktop-linux-listener-audit.sh' \
  '"$STATE_DIR/peer-process.pid"'
require_tokens "$PEER" "run-scoped daemon singleton" \
  'install -d -m 0700 "/run/nvpn-$PEER_NETNS"' \
  '--daemon-instance "$PEER_NETNS"' \
  'rm -f "/run/nvpn-$PEER_NETNS/to.nostrvpn.nvpn.daemon.instance.lock"' \
  'rmdir "/run/nvpn-$PEER_NETNS"'
require_tokens "$WINDOWS_HOST_ENTRY" "exact Windows FIPS provenance" \
  'expected="fips_core_version: $EXPECTED_FIPS_VERSION (rev $EXPECTED_FIPS_REV)"' \
  '-ExpectedFipsRevision $(ps_quote "$EXPECTED_FIPS_REV")'
require_tokens "$WINDOWS_GUEST_ENTRY" "exact Windows FIPS runtime identity" \
  '[string]$ExpectedFipsRevision' \
  '[string]$Value -eq "$ExpectedFipsVersion (rev $ExpectedFipsRevision)"' \
  '!(Test-ExpectedFipsCoreVersion $status.daemon.state.fips_core_version)'
require_tokens "$WINDOWS_GUEST_CRASH_LIB" "exact restarted Windows FIPS identity" \
  '!(Test-ExpectedFipsCoreVersion $status.daemon.state.fips_core_version)'
if grep -Fq \
  '[string]$status.daemon.state.fips_core_version -ne $ExpectedFipsVersion' \
  "$WINDOWS_GUEST_ENTRY" "$WINDOWS_GUEST_CRASH_LIB"; then
  fail "Windows runtime still compares verbose FIPS identity to a bare version"
fi
require_tokens "$ROOT/scripts/macos-release-fips-peer-remote.sh" \
  "macOS/Vader dual-family listener ownership integration" \
  'nvpn_require_dual_family_udp_listeners'

for host_gate in "$WINDOWS_HOST" "$LINUX_HOST"; do
  require_tokens "$host_gate" "real topology/cleanup evidence" \
    'virsh net-create' \
    'virsh attach-interface' \
    'virsh detach-interface' \
    'virsh domif-setlink' \
    'set_primary_link down' \
    'set_primary_link up' \
    'assert_peer_recovered_from_source' \
    'peer_command wireguard-audit' \
    'wireguard-underlay.pcap.txt' \
    'wireguard_endpoint_route' \
    'audit_hypervisor_cleanup' \
    'trap cleanup EXIT INT TERM'
  grep -Fq 'RECOVERY_DEADLINE_MS="${NVPN_DESKTOP_UNDERLAY_RECOVERY_DEADLINE_MS:-4000}"' \
    "$host_gate" \
    || fail "$(basename "$host_gate") does not enforce the four-second bound"
  if [[ "$host_gate" == "$WINDOWS_HOST" ]]; then
    require_tokens "$host_gate" "packaged Windows candidate pin" \
      'ARTIFACT_APP_SHA=' \
      'ARTIFACT_APP_TREE=' \
      'NVPN_WINDOWS_HOST_SOURCE_FIPS_RECEIPT_PATH' \
      'windows-cratesio-provenance' \
      'NVPN_WINDOWS_GIT_SYNC_EXACT_APP_COMMIT="$harness_sha"' \
      'Windows packaged app revision/tree is unavailable or inconsistent' \
      'Windows checkout differs from the exact harness revision/tree'
  else
    grep -Fq \
      'expected_tree="$(git -C "$RELEASE_APP_ROOT" rev-parse '\''HEAD^{tree}'\'')"' \
      "$host_gate" \
      || fail "$(basename "$host_gate") does not pin the product candidate tree"
    grep -Fq 'revision/tree differs from the release candidate' "$host_gate" \
      || fail "$(basename "$host_gate") does not reject mismatched revision/tree"
  fi
  if grep -Fq "current_tree" "$host_gate" \
    || grep -Fq 'git -C "$repo" add -A' "$host_gate"
  then
    fail "$(basename "$host_gate") can snapshot a realized working-tree lock"
  fi
  if grep -Eq '\b(networksetup|scutil|route -n add|ifconfig en[0-9])\b' "$host_gate"; then
    fail "$(basename "$host_gate") can mutate the controlling Mac network"
  fi
  grep -Fq 'date +%s.%N; virsh domif-setlink' "$host_gate" \
    || fail "$(basename "$host_gate") starts its four-second clock after virsh returns"
done

for guest_gate in "$WINDOWS_GUEST" "$LINUX_GUEST"; do
  for dns_case in automatic cloudflare quad9 custom through-exit; do
    grep -Fq "$dns_case" "$guest_gate" \
      || fail "$(basename "$guest_gate") omits the $dns_case DNS setting"
  done
  require_tokens "$guest_gate" "production recovery evidence" \
    'daemon' \
    'underlay carrier(s) rebound' \
    'exit-node-leak-protection' \
    'wireguard-exit-config-file' \
    'wireguard-exit-enabled' \
    'wireguard_payload_successes_after' \
    'wireguard_endpoint_route' \
    'wireguard_interface_removed' \
    'wireguard_endpoint_route_removed' \
    'select-direct' \
    'verified_https'
done
grep -Fq '$rebindAfter -ne ($rebindBefore + 1)' "$WINDOWS_GUEST" \
  || fail "Windows guest does not require exactly one rebind per physical switch"
grep -Fq '$(rebind_count) == rebind_before + 1' "$LINUX_GUEST" \
  || fail "Linux guest does not require exactly one rebind per physical switch"
[[ "$(grep -Fc '.rebind_receipts_after == (.rebind_receipts_before + 1)' "$WINDOWS_HOST")" -eq 1 \
  && "$(grep -Fc '  validate_guest_recovery_receipt \' "$WINDOWS_HOST")" -eq 2 ]] \
  || fail "Windows host does not apply one canonical rebind check to both switches"
[[ "$(grep -Fc '.rebind_receipts_after == (.rebind_receipts_before + 1)' "$LINUX_HOST")" -eq 2 ]] \
  || fail "Linux host does not independently require one rebind for both switches"

require_tokens "$WINDOWS_GUEST" "PID-bound continuous payload" \
  'Get-DaemonPid' \
  'Invoke-BoundedProbeProcess "$env:SystemRoot\System32\PING.EXE"'
require_tokens "$LINUX_GUEST" "PID-bound continuous payload" \
  'daemon_pid()' 'ping -D -n -i 0.1'
require_tokens "$LINUX_GUEST" "production SIGKILL/startup-repair evidence" \
  'crash_repair_gate()' \
  'CLEANUP_JOURNAL="$STATE_DIR/.nvpn-network-cleanup/daemon.cleanup.json"' \
  'kill -KILL "$CRASH_CONNECT_PID"' \
  'cleanup journal lacks exact WireGuard and secure-DNS ownership' \
  'SIGKILL journal lost exact WireGuard or secure-DNS ownership' \
  'assert_wireguard_endpoint_route "$primary_iface"' \
  'wireguard_latest_handshake' \
  'assert_secure_dns' \
  'resolve_fixture' \
  'test_https' \
  '    --paused \' \
  'assert_single_nvpn_process "$CRASH_RESTART_PID"' \
  'secure_dns_cleanup_ownership_survived_sigkill: true' \
  'secure_dns_cleanup_ownership_removed: true' \
  'startup_repair_without_explicit_command: true' \
  'restart_repair_milliseconds'
require_tokens "$LINUX_HOST" "mandatory SIGKILL/startup-repair receipt" \
  'run_sigkill_restart_recovery()' \
  'run_guest_primary crash-repair' \
  'crash-repair.receipt.json' \
  'crash-journal-ownership.json' \
  '.binary_sha256 == $binary_sha256' \
  '.sigkill_exit_code == 137' \
  '.secure_dns_cleanup_ownership_survived_sigkill == true' \
  '.secure_dns_cleanup_ownership_removed == true' \
  '.startup_repair_without_explicit_command == true' \
  '.restart_daemon_count == 1' \
  '.restart_repair_milliseconds <= $deadline'
require_tokens "$LINUX_HOST" "cleanup-fault failure evidence before teardown" \
  'NVPN_LINUX_UNDERLAY_CLEANUP_FAULT_DIAGNOSTIC:-0' \
  'run_optional_cleanup_fault_regression()' \
  '>"$ARTIFACT_DIR/cleanup-fault.log" 2>&1' \
  'cleanup-fault-command-status.txt' \
  'capture_cleanup_fault_diagnostics' \
  'cleanup-fault.receipt.json' \
  'xtables-stop.log' \
  'fault-daemon.stdout.log' \
  'fault-daemon.stderr.log' \
  'xtables-lock-held' \
  'xtables-lock-release'
require_tokens "$PEER" "reverse payload and physical source capture" \
  'ping -D -n -i 0.1' 'tcpdump -n -tt -l -i any'
require_tokens "$PEER" "WireGuard/DNS responder evidence" \
  'ip link add dev "$WG_IFACE" type wireguard' \
  'allowed-ips "$WG_CLIENT_ADDRESS"' \
  'listen-address="$wg_server_ip"' \
  '"udp port $WG_LISTEN_PORT"' \
  'wireguard-underlay.pcap.txt' \
  'wg show "$WG_IFACE" latest-handshakes' \
  'wg show "$WG_IFACE" transfer' \
  'iptables -t mangle -I PREROUTING' \
  'profile_dns=' \
  '8.8.8.8' \
  '8.8.4.4' \
  'counter_for_dns_destinations "${WG_SERVER_ADDRESS%/*}"' \
  'fixture_dns='
for host_gate in "$WINDOWS_HOST" "$LINUX_HOST"; do
  require_tokens "$host_gate" "exclusive desktop DNS path mapping" \
    'counters=(profile_dns cloudflare quad9 google fixture_dns)' \
    'run_dns_case automatic profile_dns'
done
require_tokens "$WINDOWS_GUEST_ENTRY" "applied Windows DNS configuration barrier" \
  $'Invoke-Nvpn (@("set", "--config", $Config) + $SetArguments)\n  Write-Marker "dns-$Name.configured" "ok"\n  Wait-ForFile "dns-$Name.query"'
require_tokens "$WINDOWS_HOST_ENTRY" "post-configuration Windows DNS counter baseline" \
  $'  signal_guest "dns-$name.go"\n  wait_for_guest_marker "dns-$name.configured" 35\n  before="$(stable_dns_counters)"\n  signal_guest "dns-$name.query"'
require_tokens "$WINDOWS_GUEST" "WireGuard-side through-exit DNS" \
  'WireGuardServerIp' \
  'exit-dns-through-exit-servers", $WireGuardServerIp'
require_tokens "$LINUX_GUEST" "WireGuard-side through-exit DNS" \
  'NVPN_UNDERLAY_WG_SERVER_IP' \
  'exit-dns-through-exit-servers "$WG_SERVER_IP"'
require_tokens "$LINUX_GUEST" "quiet exclusive DNS counter window" \
  'pause_wireguard_payload_loop' \
  'write_marker "dns-$name.configured"' \
  'wait_for_marker "dns-$name.query"' \
  'wait_for_marker "dns-$name.snapshotted"' \
  'resume_wireguard_payload_loop'
require_tokens "$LINUX_HOST_ENTRY" "host-coordinated DNS counter snapshot" \
  'signal_guest "dns-$name.go"' \
  'wait_for_guest_marker "dns-$name.configured" 30' \
  'before="$(stable_dns_counters)"' \
  'signal_guest "dns-$name.query"' \
  'wait_for_guest_marker "dns-$name.receipt" 30' \
  'after="$(stable_dns_counters)"' \
  'signal_guest "dns-$name.snapshotted"' \
  'wait_for_guest_marker "dns-$name.resumed" 30'
require_tokens "$LINUX_HOST_ENTRY" "sustained DNS counter quiescence" \
  'stable_samples=0' \
  'for attempt in $(seq 1 100)' \
  'if ((stable_samples >= 20))' \
  'stable_samples=0'
direct_restore="$(
  sed -n '/^run_dns_matrix_and_direct_restore() {$/,/^}$/p' "$LINUX_HOST_ENTRY"
)"
grep -Fq 'wait_for_guest_runner_success' <<<"$direct_restore" \
  || fail "Linux Direct restoration does not wait for runner success"
grep -Fq 'run_primary sudo -n cat "$GUEST_STATE_DIR/direct.receipt.json"' \
  <<<"$direct_restore" \
  || fail "Linux Direct receipt is not collected over its restored primary path"
if grep -Fq 'wait_for_guest_marker' <<<"$direct_restore"; then
  fail "Linux host polls post-Direct evidence over the retired secondary path"
fi
require_tokens "$WINDOWS_HOST" "provenance/diagnostic evidence" \
  'exact-artifact-validation.log' \
  'payloads.cli.sha256' \
  'collect_failure_artifacts'
require_tokens "$WINDOWS_HOST_LIB" "bounded out-of-band marker probes" \
  'run_ps_secondary_bounded' \
  'ChannelTimeout=session=${channel_timeout}s'
require_tokens "$WINDOWS_GUEST" "failed-readiness diagnostics" \
  'last-condition-error.txt'
require_tokens "$WINDOWS_HOST" "isolated peer namespace lifecycle" \
  'peer_command namespace-setup' \
  'ip netns exec "$PEER_NETNS"' \
  'peer_command listener-audit' \
  'peer_command namespace-cleanup'
require_tokens "$WINDOWS_GUEST" "independent cleanup evidence" \
  '"Watchdog"' \
  'WatchdogTimeoutSeconds' \
  'Invoke-IsolatedNetworkCleanup' \
  "WireGuardTunnel$" \
  '"WireGuardProbe"' \
  'Test-WireGuardHandshake' \
  'Assert-WireGuardEndpointRoute'
require_tokens "$WINDOWS_GUEST" "bounded real payload probes" \
  'function Invoke-BoundedProbeProcess {' \
  '$process.WaitForExit($TimeoutMilliseconds)' \
  'Stop-Process -Id $process.Id -Force' \
  'Invoke-BoundedProbeProcess "$env:SystemRoot\System32\PING.EXE"' \
  'Invoke-BoundedProbeProcess "curl.exe"'
bounded_windows_probe="$({
  sed -n '/^function Invoke-BoundedProbeProcess {$/,/^}$/p' \
    "$WINDOWS_GUEST_ENTRY"
})"
if grep -Fq '$process.WaitForExit()' <<<"$bounded_windows_probe"; then
  fail "Windows payload probe retains an unbounded process wait"
fi
require_tokens "$WINDOWS_GUEST" "power-loss startup recovery evidence" \
  'Stop-Process -Id $crashedPid -Force' \
  '$CleanupJournalPath = Join-Path $StateDir "daemon.cleanup.json"' \
  'cleanup_journal_present_before_crash' \
  'cleanup_journal_survived_forced_termination' \
  'paid_exit_cleanup_ownership_removed_after_restart' \
  'crash_cleanup_journal_replaced_after_restart' \
  'active_direct_cleanup_route_count' \
  'Read-CandidateNativeWireGuardOwnership' \
  '$markerPath = "$configPath.nvpn-owner"' \
  'native WireGuard config is not in its exact owner directory' \
  'Assert-CandidateNativeWireGuardOwnershipPresent' \
  'Assert-CandidateNativeWireGuardOwnershipRemoved' \
  'native_wireguard_owner_directory_layout = $true' \
  'native_wireguard_owned_files_survived_forced_termination' \
  'native_wireguard_owned_files_removed_after_restart' \
  'selected_direct_while_daemon_stopped' \
  'Assert-SingleExactCandidateDaemon' \
  'daemon_process_count = 1' \
  'crash-recovery.receipt.json'
require_tokens "$WINDOWS_GUEST_LIB" "current native WireGuard secret ownership audit" \
  'Read-CandidateNativeWireGuardOwnership' \
  '$script:CandidateNativeWireGuardConfigRootPath' \
  '$script:CandidateNativeWireGuardOwnerDirectoryPath' \
  '$script:CandidateNativeWireGuardConfigPath' \
  '$script:CandidateNativeWireGuardOwnerMarkerPath' \
  'Assert-NativeWireGuardSecretPathAcl' \
  'AreAccessRulesProtected' \
  'S-1-5-18' \
  'S-1-5-32-544'
if grep -Fq '"nostr-vpn\wireguard\$WireGuardInterface.conf"' \
  "$WINDOWS_GUEST_LIB"
then
  fail "Windows secret ACL gate still guesses the legacy flat config path"
fi
if grep -Fq '"${path}:nvpn-owner"' "$WINDOWS_GUEST_LIB"; then
  fail "Windows secret ACL gate still guesses the legacy owner ADS"
fi
python3 - "$WINDOWS_GUEST_LIB" "$WINDOWS_GUEST_CRASH_LIB" <<'PY'
import pathlib
import sys

common = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
crash = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
acl = common[
    common.index("function Assert-NativeWireGuardSecretAcl {"):
    common.index("\nfunction Assert-NativeNetworkRestoredBeforeRepair {")
]
required_paths = (
    "$script:CandidateNativeWireGuardConfigRootPath",
    "$script:CandidateNativeWireGuardOwnerDirectoryPath",
    "$script:CandidateNativeWireGuardConfigPath",
    "$script:CandidateNativeWireGuardOwnerMarkerPath",
)
if "Read-CandidateNativeWireGuardOwnership" not in acl:
    raise SystemExit(
        "Windows live secret ACL audit does not resolve the cleanup journal"
    )
for path in required_paths:
    if path not in acl:
        raise SystemExit(
            f"Windows live secret ACL audit omits exact owned path: {path}"
        )
resolver = crash[
    crash.index("function Read-CandidateNativeWireGuardOwnership {"):
    crash.index(
        "\nfunction Assert-CandidateNativeWireGuardOwnershipPresent {"
    )
]
for evidence in (
    "$CleanupJournalPath",
    "$native.config_path",
    "$native.owner_token",
    '"$configPath.nvpn-owner"',
    "native WireGuard config is not in its exact owner directory",
    "native WireGuard owner marker does not match the cleanup journal",
):
    if evidence not in resolver:
        raise SystemExit(
            f"Windows native ownership resolver lost fail-closed evidence: {evidence}"
        )
for forbidden in (
    r"nostr-vpn\wireguard\$WireGuardInterface.conf",
    "${path}:nvpn-owner",
):
    if forbidden in acl:
        raise SystemExit(
            f"Windows live secret ACL audit retained a stale path: {forbidden}"
        )
PY
require_tokens "$WINDOWS_HOST" "power-loss receipt enforcement" \
  'wait_for_guest_marker crash-recovery.receipt.json 45' \
  'crash-recovery-receipt.json' \
  '.replacement_daemon_pid != .crashed_daemon_pid' \
  '.daemon_process_count == 1' \
  '.startup_recovery_milliseconds <= 30000' \
  '.paid_exit_cleanup_ownership_removed_after_restart == true' \
  '.crash_cleanup_journal_replaced_after_restart == true' \
  '.native_wireguard_owner_directory_layout == true' \
  '.native_wireguard_owned_files_survived_forced_termination == true' \
  '.native_wireguard_owned_files_removed_after_restart == true' \
  'CANDIDATE_NATIVE_CONFIG_PATH=' \
  'CANDIDATE_NATIVE_MARKER_PATH=' \
  'CANDIDATE_NATIVE_OWNER_DIR=' \
  'candidate-owned native WireGuard artifact remains after daemon stop' \
  'candidate-owned native WireGuard artifact remains after cleanup'
require_tokens "$NETWORK_EVIDENCE" "Windows power-loss receipt schema" \
  '"crashed_daemon_pid"' \
  '"replacement_daemon_pid"' \
  '"daemon_process_count"' \
  '"startup_recovery_milliseconds"' \
  '"native_wireguard_owned_files_removed_after_restart"'
python3 - "$WINDOWS_GUEST" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
cleanup = text[
    text.index("function Invoke-IsolatedNetworkCleanup {"):
    text.index("\nAssert-Administrator")
]
if not (
    cleanup.index("& $Binary stop")
    < cleanup.index("Stop-Process -Id $DaemonPid")
    < cleanup.index('Wait-ForCondition "exact candidate daemon termination"')
    < cleanup.index("& $Binary repair-network")
):
    raise SystemExit(
        "Windows cleanup can repair the network before the exact daemon exits"
    )
owned = text[
    text.index("function Invoke-OwnedNetworkCleanup {"):
    text.index("\nAssert-Administrator")
]
if not (
    owned.index('"cleanup-owned"')
    < owned.index("[IO.File]::Open")
    < owned.index("[IO.FileMode]::OpenOrCreate")
    < owned.index("Stop-Process -Id $RunnerPidToStop")
    < owned.index("Invoke-IsolatedNetworkCleanup")
):
    raise SystemExit(
        "Windows cleanup is not preflight-authorized and atomically claimed"
    )
if "[IO.FileShare]::None" not in owned:
    raise SystemExit("Windows cleanup lock is not process-exclusive")
if '"cleanup.lock"' not in owned or '"cleanup-owner"' in text:
    raise SystemExit("Windows cleanup retains a stale permanent owner record")
if text.count("Invoke-IsolatedNetworkCleanup -EmergencyRepair") != 1:
    raise SystemExit("Windows retains more than one direct cleanup path")

initialize = text[text.index('  "Initialize" {'):text.index('  "Probe" {')]
if not (
    initialize.index("adapter-state.json")
    < initialize.index("Assert-IsolatedNetworkPreflight")
    < initialize.index('Write-Marker "cleanup-owned"')
    < initialize.index("Enable-NetAdapter")
):
    raise SystemExit(
        "Windows initialization mutates before clean preflight ownership"
    )
preflight = text[
    text.index("function Assert-IsolatedNetworkPreflight {"):
    text.index("\nfunction Invoke-IsolatedNetworkCleanup {")
]
for fixed_resource in (
    '"NvpnService"',
    '"nvpn"',
    "$TunnelInterface",
    "$WireGuardInterface",
    "Get-SecureDnsRules",
    '"nostr-vpn\\wireguard"',
):
    if fixed_resource not in preflight:
        raise SystemExit(
            f"Windows clean preflight omits fixed resource: {fixed_resource}"
        )

watchdog = text[text.index('  "Watchdog" {'):text.index('  "Run" {')]
run = text[text.index('  "Run" {'):text.index('  "Cleanup" {')]
host_cleanup = text[text.index('  "Cleanup" {'):]
for section, owner in (
    (watchdog, "watchdog"),
    (run, "runner"),
    (host_cleanup, "host"),
):
    if f'Invoke-OwnedNetworkCleanup -Owner "{owner}"' not in section:
        raise SystemExit(f"Windows {owner} does not use claimed cleanup")
    if "Invoke-IsolatedNetworkCleanup" in section:
        raise SystemExit(f"Windows {owner} bypasses claimed cleanup")
if "-RunnerPidToStop $RunnerPid" not in watchdog:
    raise SystemExit("Windows watchdog cleanup does not first stop its runner")
if "-RunnerPidToStop $RunnerPid" not in host_cleanup:
    raise SystemExit("Windows host cleanup does not stop only after winning")
for proof in (
    'AddSeconds(90)',
    'timed out waiting for the active cleanup owner',
    '"probe.pid"',
    '"wireguard-probe.pid"',
    '"watchdog.pid"',
):
    if proof not in owned:
        raise SystemExit(f"Windows claimed cleanup lost bounded ownership proof: {proof}")
descendants = owned.index('foreach ($marker in @("probe.pid"')
native_cleanup = owned.index("Invoke-IsolatedNetworkCleanup", descendants)
complete = owned.index('Write-Marker "cleanup.complete"', native_cleanup)
release = owned.index("$lock.Dispose()", complete)
if not descendants < native_cleanup < complete < release:
    raise SystemExit("Windows cleanup completes before owned descendants stop")
if "runner-cleanup." in text:
    raise SystemExit("Windows retains duplicate runner cleanup markers")
for marker in ("probe.pid", "wireguard-probe.pid"):
    if f'Write-Marker "{marker}"' not in text:
        raise SystemExit(f"Windows runner does not record cleanup child: {marker}")
if run.index("throw $runError") > run.index("throw $cleanupError"):
    raise SystemExit("Windows cleanup error can mask the original run failure")
crash = text[text.index("function Invoke-CrashRecovery {"):]
ownership = crash.index("Read-CandidateNativeWireGuardOwnership")
termination = crash.index("Stop-Process -Id $crashedPid -Force")
if ownership >= termination:
    raise SystemExit(
        "Windows crash gate reads native WireGuard ownership after terminating it"
    )
if crash.index(
    "Assert-CandidateNativeWireGuardOwnershipPresent",
    termination,
) >= crash.index("$recoveryTimer = [Diagnostics.Stopwatch]::StartNew()"):
    raise SystemExit(
        "Windows crash gate does not prove candidate-owned files survive termination"
    )
for forbidden in ("repair-network", "Invoke-IsolatedNetworkCleanup"):
    if forbidden in crash:
        raise SystemExit(
            f"Windows crash recovery uses forbidden fallback path: {forbidden}"
        )
PY
for evidence in \
  '.wireguard_endpoint_route.interface_index == $interface_index' \
  '.wireguard_endpoint_route.next_hop == $gateway' \
  '.wireguard_endpoint_route.source_address == $source'
do
  [[ "$(grep -Fc "$evidence" "$WINDOWS_HOST")" -eq 1 ]] \
    || fail "Windows host lacks canonical endpoint-route validation: $evidence"
done
require_tokens "$WINDOWS_GUEST" "timestamped recovery receipt" \
  'One deadline-edge read accepts a delayed log write' \
  'source_address = [string]$routeDecision.source_address'
python3 - "$WINDOWS_GUEST" "$WINDOWS_HOST_ENTRY" "$WINDOWS_HOST_LIB" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
host = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
host_lib = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
observe = text[text.index("function Observe-Recovery {"):text.index("function Run-DnsSettingCase {")]
evidence = observe.index("$evidence = Wait-ForRecoveryEvidence")
audit = observe.index("Assert-ActiveExit")
elapsed = observe.index("$elapsed = [long]$evidence.recovered_unix_milliseconds")
if not evidence < audit < elapsed:
    raise SystemExit(
        "Windows recovery evidence and slower stable-state audit are not separated"
    )
if "Stopwatch]::StartNew()" in observe:
    raise SystemExit("Windows product recovery is still measured by harness wall time")
freshness = text[
    text.index("function Wait-ForRecoveryEvidence {"):
    text.index("\nfunction Observe-Recovery {")
]
for proof in (
    "$ObservationStartedUnixMilliseconds",
    "$RouteUsableUnixMilliseconds",
    "$deadlineUnixMilliseconds =",
    "$RouteUsableUnixMilliseconds + $RecoveryDeadlineMilliseconds",
    "$RebindBefore $ObservationStartedUnixMilliseconds",
    "$ProbeBefore $RouteUsableUnixMilliseconds",
    "$WireGuardProbeBefore $RouteUsableUnixMilliseconds",
):
    if proof not in freshness:
        raise SystemExit(
            f"Windows recovery accepts stale timestamp evidence: {proof}"
        )
if "[Math]::Max(\n          0," in freshness or "[Math]::Max(\n    0," in observe:
    raise SystemExit("Windows recovery still zero-clamps stale evidence")
validator = host[
    host.index("validate_guest_recovery_receipt() {"):
    host.index("\nrun_underlay_switches() {")
]
for proof in (
    ".observation_started_unix_milliseconds > 0",
    ".rebind_unix_milliseconds\n        >= .observation_started_unix_milliseconds",
    ".payload_success_unix_milliseconds\n        >= .route_usable_unix_milliseconds",
    ".wireguard_payload_success_unix_milliseconds\n        >= .route_usable_unix_milliseconds",
    "== (.recovered_unix_milliseconds - .route_usable_unix_milliseconds)",
):
    if proof not in validator:
        raise SystemExit(
            f"Windows host does not reject stale recovery evidence: {proof}"
        )
if ",\n          0\n        ] | max" in validator:
    raise SystemExit("Windows host still zero-clamps stale recovery evidence")

run = text[text.index('  "Run" {'):text.index('  "Cleanup" {')]
for label in ("secondary", "primary"):
    start = run.index(f"${label}ObservationStarted")
    rebind = run.index(f"${label}RebindBefore", start)
    armed = run.index(f'Write-Marker "armed-{label}"', rebind)
    observation = run.index(f'Observe-Recovery "{label}"', armed)
    if not start < rebind < armed < observation:
        raise SystemExit(
            f"Windows {label} freshness baseline is not captured before the cut"
        )

cleanup = host[host.index("cleanup() {"):host.index("trap cleanup EXIT INT TERM")]
for marker in (
    "arm-secondary",
    "arm-primary",
    "dns-automatic.go",
    "select-direct",
):
    if marker in cleanup:
        raise SystemExit(
            f"Windows teardown still unlocks a future mutation stage: {marker}"
        )
if cleanup.count("-Action Cleanup") != 1:
    raise SystemExit("Windows teardown must have exactly one fallback Cleanup call")
for obsolete in (
    "wait_for_windows_runner_cleanup",
    "stop_windows_runner_for_fallback",
    "guest_cleanup_marker_exists",
    "GUEST_INITIALIZATION_ATTEMPTED",
):
    if obsolete in host:
        raise SystemExit(f"Windows teardown retains obsolete ownership path: {obsolete}")
ownership = cleanup.index('ownership_state="$(guest_cleanup_ownership_state)"')
owned_case = cleanup.index("owned)", ownership)
runner_pid = cleanup.index("$GUEST_STATE_DIR\\\\runner.pid", owned_case)
fallback = cleanup.index("-Action Cleanup", runner_pid)
runner_argument = cleanup.index("-RunnerPid \\$runnerPid", fallback)
audit = cleanup.index("audit_guest_cleanup", runner_argument)
if not ownership < owned_case < runner_pid < fallback < runner_argument < audit:
    raise SystemExit("Windows host does not pass the recorded runner into claimed cleanup")
management = host[
    host.index("run_ps_cleanup_management() {"):
    host.index("\ncleanup() {")
]
for proof in (
    'run_ps_with secondary "$script" "$channel_timeout"',
    'run_ps_with primary "$script" "$channel_timeout"',
    "guest_cleanup_ownership_state",
    'echo "unknown"',
):
    if proof not in management:
        raise SystemExit(f"Windows cleanup management lost tri-state proof: {proof}")
if 'run_ps_cleanup_management \\\n' not in cleanup or " 180 " not in cleanup:
    raise SystemExit("Windows claimed cleanup lacks a bounded management channel")
quarantine = cleanup.index("QUARANTINE_GUEST_NETWORK=1", ownership)
detach_guard = cleanup.index('if [[ "$QUARANTINE_GUEST_NETWORK" == "0" ]]')
detach = cleanup.index("virsh detach-interface", detach_guard)
destroy = cleanup.index("virsh net-destroy", detach)
if not ownership < quarantine < detach_guard < detach < destroy:
    raise SystemExit("Windows unknown cleanup proof can still destroy its management path")
if "NVPN_WINDOWS_UNDERLAY_WG_INTERFACE" in host:
    raise SystemExit("Windows gate retains a partially propagated WireGuard knob")
if 'primary_ssh_command "$channel_timeout"' not in host_lib:
    raise SystemExit("Windows partial-init cleanup transport is unbounded")
if "\\$processMarkers = @('probe.pid', 'wireguard-probe.pid', 'watchdog.pid')" not in host:
    raise SystemExit("Windows cleanup audit omits recorded child processes")
PY
[[ "$(grep -Fc 'assert_peer_recovered_from_source "$cut"' "$WINDOWS_HOST")" -eq 2 ]] \
  || fail "Windows peer evidence is not clocked from each hypervisor link cut"
require_tokens "$WINDOWS_HOST" "root-readable exact peer observation" \
  'sudo -n bash -s --' \
  '"$RECOVERY_DEADLINE_MS" "$label" <"$observer"' \
  'decimal_seconds_to_ns' \
  'evidence_deadline_ns="$((cut_ns + deadline_ns))"' \
  'flush_deadline_ns="$((evidence_deadline_ns + FLUSH_GRACE_MS * 1000000))"'
grep -Fq 'wait_for_guest_marker ready 35' "$WINDOWS_HOST" \
  || fail "Windows runtime readiness still has an unreasonable host-side wait"
if grep -Fq '90000' "$WINDOWS_GUEST" \
  || grep -Fq '120000' "$WINDOWS_GUEST" \
  || grep -Fq 'wait_for_guest_marker ready 120' "$WINDOWS_HOST"
then
  fail "Windows runtime readiness retains a 90/120-second fallback window"
fi
require_tokens "$WINDOWS_HOST" "exact provenance/artifact-import contract" \
  'the exact FIPS release-gate checkout must be committed and clean' \
  'checkout --detach' \
  'target-version.txt' \
  'peer-version.txt' \
  'Windows underlay CLI differs from the exact installed-and-launched installer payload' \
  'WINDOWS_EXACT_INSTALLER_CLI_SHA256=' \
  'desktop_underlay_import_host_peer'

require_tokens "$RELEASE_GATE" "real auto-discoverable underlay lane" \
  'windows-vm-desktop-underlay-change-e2e.sh' \
  'linux-vm-desktop-underlay-change-e2e.sh' \
  'NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E:-auto' \
  'NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E:-auto'
require_tokens "$LOCAL_RELEASE" "mandatory publication lane" \
  "NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E: '1'" \
  "NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E: '1'" \
  "NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E: '1'" \
  "NVPN_RELEASE_GATE_MACOS_GUI_SMOKE: '1'" \
  "NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU: '1'"
require_tokens "$RELEASE_GATE" "isolated macOS network/service lanes" \
  'macos-vm-desktop-wireguard-exit-e2e.sh' \
  'macos-vm-desktop-app-launch-smoke.sh' \
  'macos-vm-desktop-daemon-idle-e2e.sh'
require_tokens "$MACOS_WIREGUARD" "real imported macOS network gate" \
  'lib-macos-vm-imported-release.sh' \
  'lib-mobile-wireguard-fixture.sh' \
  'macos_vm_prepare_or_verify_imported_release' \
  'NVPN_MACOS_VM_IMPORT_ONLY=1' \
  'NVPN_E2E_BINARY=' \
  './scripts/e2e-macos-release-network.sh' \
  'NVPN_MACOS_WG_FIXTURE_HOST_IP' \
  'unset NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST' \
  'MOBILE_WG_FIXTURE_ENDPOINT_FAMILY" == "ipv4"' \
  'mobile_wg_fixture_wg_bytes' \
  'mobile_wg_fixture_forward_packets' \
  'mobile_wg_fixture_dns_evidence_snapshot' \
  'wait_for_fixture_dns_quiet' \
  'DNS counters did not settle after transition' \
  'DNS_CASE_PROBE_HOST="measure-$PPID-$RANDOM.$transition_probe_host"' \
  'mobile_wg_fixture_assert_dns_case_evidence' \
  'mobile_wg_fixture_cleanup'
if grep -Fq 'requires the remote Vader fixture' "$MACOS_WIREGUARD" \
  || grep -Fq 'discover_remote_fixture_ipv4' "$MACOS_WIREGUARD" \
  || grep -Fq 'mobile_wg_remote_exec' "$MACOS_WIREGUARD" \
  || grep -Fq 'FIPS_PEER_SSH_HOST' "$MACOS_WIREGUARD"
then
  fail "macOS network fixture still depends on a remote fixture host"
fi
for dns_case in \
  automatic-profile cloudflare-doh quad9-doh custom-doh through-exit
do
  grep -Fq "$dns_case" "$MACOS_WIREGUARD" \
    || fail "macOS host gate omits the $dns_case real resolver case"
done
require_tokens "$MACOS_NETWORK_GUEST" "production macOS transition evidence" \
  'NVPN_MACOS_VM_IMPORT_ONLY' \
  'codesign --verify --strict' \
  'wireguard-exit-config-file' \
  'wireguard-exit-enabled' \
  'exit-dns-mode' \
  'exit-dns-doh-provider' \
  'exit-dns-custom-doh-url' \
  'exit-dns-custom-doh-bootstrap-ips' \
  'exit-dns-through-exit-servers' \
  'runtime_dns_state_matches' \
  'normalize_scutil_dns_file' \
  '/etc/resolver/nvpn-secure-dns' \
  'scutil --dns' \
  'networksetup -setnetworkserviceenabled' \
  'Ethernet' \
  'Roaming Underlay' \
  'NVPN_MACOS_UNDERLAY_RECOVERY_DEADLINE_MS:-4000' \
  'FIPS underlay carrier(s) rebound' \
  'runtime_wireguard_state_is false true' \
  'runtime_wireguard_state_is false false' \
  'wait_for_crash_live_precondition' \
  'crash_fail_closed_after_sigkill' \
  'crash_restart_transport_live' \
  'crash_restart_payloads_live' \
  'record_crash_restart_probe' \
  'crash-restart-probes' \
  'runtime_has_no_fips_peers' \
  'expected_bind_receipts=1' \
  'startup_persist_path_completed=true' \
  'sigkill_tunnel_routes_absent=true' \
  'sigkill_secure_dns_ownership_seen=true' \
  'sudo -n /bin/kill -KILL "$old_pid"' \
  'MACOS_RELEASE_NETWORK_CRASH_RESTART_OK' \
  'select-direct' \
  'direct-source-ip' \
  'direct_source_ip=' \
  'forwarded_probe_live=true' \
  'endpoint_route_interface' \
  'MACOS_RELEASE_NETWORK_DIRECT_OK'
crash_restart_transport_body="$(
  sed -n '/^crash_restart_transport_live() {$/,/^}$/p' \
    "$MACOS_NETWORK_GUEST"
)"
grep -Fq 'crash_restart_payloads_live' <<<"$crash_restart_transport_body" \
  || fail "macOS timed crash recovery omits authenticated payload probes"
if grep -Fq 'runtime_fips_peer_connected' "$MACOS_NETWORK_GUEST"; then
  fail "macOS WireGuard gate still depends on an authenticated FIPS peer"
fi
require_tokens "$WIREGUARD_FIXTURE_LIB" "independent resolver endpoints" \
  'https://dns.google/dns-query' \
  '8.8.8.8' \
  'dns-through'
require_tokens "$MACOS_WIREGUARD" "distinct through-exit DNS address" \
  'NVPN_MACOS_WG_THROUGH_DNS_IP:-10.99.79.53'
for forbidden in \
  'cargo build' \
  'xcodebuild' \
  'macos-build' \
  'codesign --force' \
  '/usr/bin/swift' \
  'swift -e' \
  'swiftc'
do
  if grep -Fq "$forbidden" "$MACOS_NETWORK_GUEST"; then
    fail "macOS guest network path can build/sign in the VM: $forbidden"
  fi
done
[[ "$(grep -Fc 'connected_peer_count") == "0"' "$NETWORK_EVIDENCE")" == 2 ]] \
  || fail "macOS release evidence does not preserve the isolated zero-peer runtime contract"

MACOS_DEFINITIONS="$COMBINED_DIR/macos-network-definitions.sh"
sed '/^validate_inputs$/,$d' "$MACOS_NETWORK_GUEST" >"$MACOS_DEFINITIONS"

SCUTIL_FIXTURES="$COMBINED_DIR/scutil"
mkdir -p "$SCUTIL_FIXTURES"
cat >"$SCUTIL_FIXTURES/baseline.txt" <<'EOF'
DNS configuration

resolver #1
  search domain[0] : example.test
  nameserver[0] : 192.0.2.53
  if_index : 4 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 200000

resolver #2
  domain   : local
  nameserver[0] : 192.0.2.54
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
EOF
cat >"$SCUTIL_FIXTURES/reordered.txt" <<'EOF'
DNS configuration

resolver #9
  domain   : local
  nameserver[0] : 192.0.2.54
  reach    : 0x00000000 (Not Reachable)
  order    : 900000

resolver #3
  nameserver[0] : 192.0.2.53
  search domain[0] : example.test
  if_index : 99 (en0)
  flags    : Request A records, Scoped
  reach    : 0x00000000 (Not Reachable)
  order    : 100
EOF
cat >"$SCUTIL_FIXTURES/leaked.txt" <<'EOF'
DNS configuration

resolver #1
  search domain[0] : example.test
  nameserver[0] : 203.0.113.53
  if_index : 4 (en0)
  flags    : Scoped, Request A records

resolver #2
  domain   : local
  nameserver[0] : 192.0.2.54
EOF
for fixture in baseline reordered leaked; do
  bash -s -- \
    "$MACOS_DEFINITIONS" \
    "$SCUTIL_FIXTURES/$fixture.txt" \
    "$SCUTIL_FIXTURES/$fixture.json" <<'BASH'
set -euo pipefail
definitions="$1"
input="$2"
output="$3"
set -- definitions-only
# shellcheck disable=SC1090
source "$definitions"
normalize_scutil_dns_file "$input" "$output"
BASH
done
cmp -s "$SCUTIL_FIXTURES/baseline.json" "$SCUTIL_FIXTURES/reordered.json" \
  || fail "semantic scutil normalization rejects reordered equivalent resolvers"
if cmp -s "$SCUTIL_FIXTURES/baseline.json" "$SCUTIL_FIXTURES/leaked.json"; then
  fail "semantic scutil normalization accepted a nameserver leak"
fi

UNDERLAY_PROBE_DIR="$COMBINED_DIR/underlay-probe"
mkdir -p "$UNDERLAY_PROBE_DIR/state/results"
UNDERLAY_PROBE="$UNDERLAY_PROBE_DIR/e2e-macos-release-network.sh"
cat >"$UNDERLAY_PROBE" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1090
source "$NVPN_TEST_MACOS_DEFINITIONS"
mkdir -p "$RESULT_DIR"
printf '0\n' >"$STATE_DIR/rebind-baseline"
printf '0\n' >"$STATE_DIR/wireguard-rebind-baseline"
printf '%s\n' "$$" >"$STATE_DIR/underlay.pid"
process_start_signature "$$" >"$STATE_DIR/underlay.start"
payload_loop() {
  while true; do
    sleep 1
  done
}
runtime_has_no_fips_peers() {
  return 0
}
wireguard_interface() {
  printf 'utun9\n'
}
monotonic_ms() {
  printf '1\n'
}
sudo() {
  return 37
}
restore_saved_service_states() {
  return 0
}
wait_for_cleanup_condition() {
  return 0
}
repair_owned_network_to_direct() {
  return 0
}
run_underlay_with_status
BASH
chmod +x "$UNDERLAY_PROBE"
set +e
env \
  NVPN_TEST_MACOS_DEFINITIONS="$MACOS_DEFINITIONS" \
  NVPN_MACOS_NETWORK_WAIT_SECS=1 \
  NVPN_MACOS_NETWORK_STATE_DIR="$UNDERLAY_PROBE_DIR/state" \
  bash "$UNDERLAY_PROBE" underlay-run \
  >"$UNDERLAY_PROBE_DIR/probe.log" 2>&1
underlay_probe_status="$?"
set -e
[[ "$underlay_probe_status" -eq 37 ]] \
  || fail "mid-gate failure escaped with status $underlay_probe_status instead of 37"
[[ "$(<"$UNDERLAY_PROBE_DIR/state/underlay.status")" == "fail:37" ]] \
  || fail "mid-gate failure was not recorded fail-closed"
if grep -Fq 'MACOS_RELEASE_NETWORK_UNDERLAY_OK' "$UNDERLAY_PROBE_DIR/probe.log"; then
  fail "mid-gate failure reached the underlay success marker"
fi
[[ ! -e "$UNDERLAY_PROBE_DIR/state/payload.pid" ]] \
  || fail "mid-gate failure left its owned payload receipt/process"

CLEANUP_PROBE="$COMBINED_DIR/macos-cleanup-probe.sh"
cat >"$CLEANUP_PROBE" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1090
source "$NVPN_TEST_MACOS_DEFINITIONS"
WAIT_SECS=1
repair_owned_network_to_direct() { return 0; }
saved_direct_baseline_available() { return 0; }
restore_saved_service_states() { return 0; }
direct_state_matches() { return 1; }
exact_direct_dns_matches() { return 0; }
saved_service_states_match() { return 0; }
resolver_files_absent() { return 0; }
pgrep() { return 1; }
cleanup_gate
BASH
chmod +x "$CLEANUP_PROBE"
set +e
env \
  NVPN_TEST_MACOS_DEFINITIONS="$MACOS_DEFINITIONS" \
  NVPN_MACOS_NETWORK_STATE_DIR="$COMBINED_DIR/cleanup-state" \
  bash "$CLEANUP_PROBE" definitions-only >/dev/null 2>&1
cleanup_probe_status="$?"
set -e
[[ "$cleanup_probe_status" -ne 0 ]] \
  || fail "cleanup passed while a saved Direct route remained unrestored"

if grep -Fq './scripts/e2e-wireguard-exit-host.sh' "$MACOS_WIREGUARD"; then
  fail "macOS release network gate still uses the scoped-host self-test"
fi
for forbidden_host_path in \
  './scripts/e2e-wireguard-exit-host.sh' \
  './scripts/macos-app-launch-smoke.sh' \
  './scripts/e2e-macos-service.sh'
do
  if grep -Fq "$forbidden_host_path" "$RELEASE_GATE"; then
    fail "release gate can mutate its macOS host: $forbidden_host_path"
  fi
done

python3 - "$RELEASE_GATE" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
linux_start = text.index("run_linux_exclusive_desktop_gates() {")
windows_start = text.index("run_windows_exclusive_desktop_gates() {")
macos_start = text.index("run_macos_exclusive_desktop_gates() {")
serial_end = text.index("\nrelease_gate_perf_output_dir() {", macos_start)
linux = text[linux_start:windows_start]
windows = text[windows_start:macos_start]
macos = text[macos_start:serial_end]
if "run_linux_platform_lane" in linux:
    raise SystemExit("exclusive Linux underlay tail still performs build/UI prep")
if "run_linux_underlay_network_change_gate" not in linux:
    raise SystemExit("exclusive Linux tail omits the underlay timing gate")
if "run_windows_platform_lane" in windows:
    raise SystemExit("exclusive Windows network tail still performs build/UI prep")
windows_order = [
    windows.index("run_windows_wireguard_exit_gate"),
    windows.index("run_windows_underlay_network_change_gate"),
]
if windows_order != sorted(windows_order):
    raise SystemExit("Windows WireGuard proof does not precede underlay timing")
if "run_macos_platform_lane" in macos:
    raise SystemExit("exclusive macOS network tail still performs build/UI prep")
if "run_wireguard_exit_platform_gates" not in macos:
    raise SystemExit("exclusive macOS network tail omits its WireGuard proof")

main_start = text.index("main() {")
main_end = text.rindex('\nmain "$@"')
main = text[main_start:main_end]
prep = [
    '"Windows platform"',
    '"macOS platform UI"',
    '"Linux platform UI"',
]
prep_positions = [main.index(item) for item in prep]
host_validation = main.index('"Host static and Rust validation"')
if any(position >= host_validation for position in prep_positions):
    raise SystemExit("an isolated desktop lane starts after host validation")
join_positions = [
    main.index(
        'release_gate_parallel_wait_group "${concurrent_validation_lanes[@]}"'
    )
]
order = [
    "run_desktop_app_launch_smokes",
    "run_linux_exclusive_desktop_gates",
    "run_windows_exclusive_desktop_gates",
    "run_macos_exclusive_desktop_gates",
    "run_mobile_qr_join_latency_gate",
    "run_public_fips_transit_gate",
    "run_docker_signal_gates",
    "run_docker_isolated_functional_gates",
    "run_docker_perf_gate",
    "./scripts/release-gate-host-pair-latency.sh",
    "./scripts/release-gate-host-pair-loaded-latency.sh",
    "run_macos_daemon_idle_cpu_gate",
    "run_mobile_idle_cpu_gates",
    "run_mobile_wireguard_exit_gates",
    "run_android_legacy_replacement_gate",
    "run_mobile_underlay_change_gates",
    "run_mobile_join_e2e_gate",
]
positions = [main.index(item) for item in order]
if max(join_positions) >= positions[0] or positions != sorted(positions):
    raise SystemExit("exclusive desktop/device/measurement tail is out of order")
if any(position >= positions[0] for position in join_positions):
    raise SystemExit("a desktop prep lane is not joined before exclusive network gates")
for receipt in (
    "NVPN_MOBILE_ANDROID_RELEASE_RECEIPT",
    "NVPN_MOBILE_IOS_RELEASE_RECEIPT",
):
    if receipt not in main:
        raise SystemExit(f"mobile exact-artifact receipt setup was dropped: {receipt}")
for forbidden in (
    "./scripts/e2e-wireguard-exit-host.sh",
    "./scripts/macos-app-launch-smoke.sh",
    "./scripts/e2e-macos-service.sh",
):
    if forbidden in main:
        raise SystemExit(f"release main retains forbidden host/concurrent path: {forbidden}")
PY

for host_gate in "$WINDOWS_HOST_ENTRY" "$LINUX_HOST_ENTRY"; do
  require_tokens "$host_gate" "host-built peer import-only contract" \
    'lib-desktop-underlay-host-peer.sh' \
    'desktop_underlay_import_host_peer' \
    'desktop_underlay_cleanup_host_peer'
  if grep -Fq 'peer-build.log' "$host_gate"; then
    fail "$(basename "$host_gate") still compiles its peer on Vader"
  fi
done
require_tokens "$HOST_PEER_IMPORT" "immutable Mac-to-Vader peer import" \
  'prepare-macos-release-fips-peer.sh' \
  'verify-host-linux-peer-artifact.py' \
  'mktemp -d /tmp/nvpn-desktop-underlay-peer.XXXXXX' \
  'builtOnHostMac' \
  'builtOnRemoteVm' \
  'host-peer-import-receipt.txt' \
  'test ! -e "$remote_dir"'
for forbidden in 'cargo build' 'cargo check' 'cargo run' 'rustc '; do
  if grep -Fq "$forbidden" "$HOST_PEER_IMPORT"; then
    fail "Vader peer importer can compile: $forbidden"
  fi
done
for forbidden in 'cargo ' 'rustc ' 'target-linux-check.log' 'GUEST_FIPS_REPO'; do
  if grep -Fq "$forbidden" "$LINUX_HOST_ENTRY"; then
    fail "Linux underlay VM wrapper can compile or validate source remotely: $forbidden"
  fi
done
for evidence in \
  'host-peer-import.log' \
  'linux-binary-sha256.txt' \
  'desktop_underlay_import_host_peer' \
  'GUEST_IMPORT_DIR="/tmp/nvpn-linux-underlay-release-$RUN_TOKEN"' \
  'TARGET_RELEASE_SIZE' \
  'tested-artifact-receipt.json' \
  'tested-artifact.json' \
  'builderMode=%s' \
  'builtOnHostMac=%s' \
  'builtOnRemoteVm=%s' \
  'targetImportDirectoryUnique=true' \
  'cleanup_guest_import' \
  'target-import-cleanup-audit.txt'
do
  grep -Fq "$evidence" "$LINUX_HOST_ENTRY" \
    || fail "Linux host import-only target contract is missing: $evidence"
done
grep -Fq '[[ "$source_sha" == "$target_sha" ]]' "$LINUX_HOST" \
  && grep -Fq '[[ "$peer_sha" == "$DESKTOP_UNDERLAY_HOST_PEER_SHA256" ]]' "$LINUX_HOST" \
  && grep -Fq -- '--arg binary_sha256 "$TARGET_RELEASE_SHA256"' "$LINUX_HOST" \
  || fail "Linux target/fixture hashes are not independently bound"
for evidence in \
  'peer_command namespace-setup' \
  'ip netns exec "$PEER_NETNS"' \
  'peer_command listener-audit' \
  'peer_command namespace-cleanup'
do
  grep -Fq "$evidence" "$LINUX_HOST" \
    || fail "Linux peer does not use the isolated production-binding namespace: $evidence"
done
for evidence in \
  'ip netns add "$PEER_NETNS"' \
  'ip link add "$PEER_HOST_VETH" type veth' \
  'iptables -t nat -I POSTROUTING 1 -j "$PEER_NAT_CHAIN"' \
  'iptables -I FORWARD 1 -j "$PEER_FORWARD_CHAIN"' \
  'MASQUERADE' \
  'listener-audit'
do
  grep -Fq "$evidence" "$PEER" \
    || fail "peer fixture lacks namespace routing/binding evidence: $evidence"
done
grep -Fq 'wait_for_guest_marker ready 35' "$LINUX_HOST" \
  || fail "Linux runtime readiness still has an unreasonable host-side wait"
grep -Fq 'for _ in $(seq 1 300)' "$PEER" \
  || fail "peer readiness is not bounded to thirty seconds"
if grep -Fq 'for _ in $(seq 1 900)' "$PEER" \
  || grep -Fq 'SECONDS + 90' "$LINUX_GUEST" \
  || grep -Fq 'wait_for_guest_marker ready 120' "$LINUX_HOST"
then
  fail "Linux runtime readiness retains a 90/120-second fallback window"
fi
grep -Fq 'initial_route=' "$LINUX_GUEST" \
  || fail "Linux initial readiness timeout does not report its last route condition"
grep -Fq 'tail -n 80 "$STATE_DIR/daemon.stderr.log"' "$LINUX_GUEST" \
  || fail "Linux initial readiness timeout does not report its daemon log"
grep -Fq '.status_source == "daemon"' "$PEER" \
  || fail "peer readiness does not parse daemon state semantically"
grep -Fq '.daemon.state.connected_peer_count >= 1' "$PEER" \
  || fail "peer readiness can pass without a real connected session"
grep -Fq 'jq -e . "$ARTIFACT_DIR/peer-ready.json"' "$LINUX_HOST" \
  || fail "Linux gate does not reject a contaminated peer status receipt"
for receipt in \
  peer-ready.json secondary-receipt.json primary-receipt.json direct-receipt.json \
  crash-repair-receipt.json
do
  grep -Fq "jq -e . \"\$ARTIFACT_DIR/$receipt\"" "$LINUX_HOST" \
    || fail "Linux gate does not validate JSON receipt: $receipt"
done
python3 - "$LINUX_HOST_ENTRY" "$LINUX_GUEST" <<'PY'
import pathlib
import sys

host = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
guest = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
host_order = (
    host.index("run_dns_matrix_and_direct_restore\n"),
    host.index("run_sigkill_restart_recovery\n"),
    host.index("run_optional_cleanup_fault_regression\n"),
)
if host_order != tuple(sorted(host_order)):
    raise SystemExit(
        "Linux SIGKILL recovery does not run after real DNS/Direct and before cleanup fault"
    )
crash = guest[
    guest.index("crash_repair_gate() {"):
    guest.index("\ncleanup_gate() {")
]
crash_order = (
    crash.index('resolve_fixture'),
    crash.index('kill -KILL "$CRASH_CONNECT_PID"'),
    crash.index('[[ -s "$CLEANUP_JOURNAL" ]]', crash.index('kill -KILL')),
    crash.index('"$BINARY" daemon \\\n    --paused'),
    crash.index('[[ ! -e "$CLEANUP_JOURNAL" ]]'),
    crash.index('assert_single_nvpn_process "$CRASH_RESTART_PID"'),
)
if crash_order != tuple(sorted(crash_order)):
    raise SystemExit(
        "Linux crash gate does not prove traffic, SIGKILL persistence, startup repair, and singleton in order"
    )
restart = crash.index('"$BINARY" daemon \\\n    --paused')
final_network_predicate = crash.index("&& test_https", restart)
final_repair_clock = crash.index(
    'restart_repaired_at="$(monotonic_milliseconds)"',
    final_network_predicate,
)
receipt_clock = crash.index(
    '--argjson restart_repair_milliseconds "$restart_elapsed"',
    final_repair_clock,
)
if not final_network_predicate < final_repair_clock < receipt_clock:
    raise SystemExit(
        "Linux crash-repair receipt stops its four-second clock before final DNS/HTTPS assertions"
    )
if "repair-network" in crash:
    raise SystemExit("Linux crash gate can bypass startup recovery with explicit repair-network")
PY
grep -Fq 'version --verbose' "$LINUX_HOST" \
  || fail "Linux gate does not capture immutable target/peer version receipts"
grep -Fq 'NVPN_UNDERLAY_EXPECTED_FIPS_REV' "$LINUX_GUEST" \
  || fail "Linux target runtime does not assert the expected FIPS revision"
grep -Fq 'NVPN_UNDERLAY_EXPECTED_FIPS_REV' "$PEER" \
  || fail "Linux peer runtime does not assert the expected FIPS revision"
for value in \
  NVPN_UNDERLAY_SECONDARY_ADDRESS \
  NVPN_UNDERLAY_SECONDARY_PREFIX \
  NVPN_UNDERLAY_SECONDARY_GATEWAY
do
  grep -Fq "\"$value=" "$LINUX_HOST" \
    || fail "Linux guest environment does not receive $value"
done
[[ "$(grep -Fc 'linux_guest_env' "$LINUX_HOST")" -eq 3 ]] \
  || fail "Linux primary and detached guest actions do not share one environment"
grep -Fq '"$SECONDARY_ADDRESS" "$SECONDARY_GATEWAY"' "$LINUX_GUEST" \
  || fail "Linux run action does not require the initialized secondary values"
grep -Fq 'nmcli device set "$secondary_iface" managed no' "$LINUX_GUEST" \
  || fail "NetworkManager can erase the real secondary underlay during the gate"
if grep -Fq 'SECONDS + 120' "$LINUX_GUEST"; then
  fail "Linux guest retains an unbounded internal marker wait"
fi
grep -Fq "virsh domif-getlink \"\$vm\" \"\$primary_iface\" | awk '{ print \$NF }'" \
  "$LINUX_HOST" \
  || fail "Linux cleanup audit compares the unparsed virsh link row"
grep -Fq 'capture_remote_state' "$LINUX_HOST" \
  || fail "Linux failure cleanup does not preserve guest and peer evidence"
require_tokens "$LINUX_HOST_LIB" "detached fail-closed guest-runner supervision" \
  'run_secondary_bounded()' \
  'run_hypervisor_bounded()' \
  'start_guest_secondary_unit()' \
  'systemd-run' \
  '--collect' \
  '--property=Type=exec' \
  '--property=RemainAfterExit=yes' \
  '--property=RuntimeMaxSec=600' \
  '--property=StandardOutput=append:' \
  '--property=StandardError=append:' \
  '--property=ActiveState' \
  '--property=Result' \
  '--property=ExecMainStatus' \
  'wait_for_guest_runner_success()' \
  'systemctl stop' \
  'ConnectionAttempts=1' \
  'ServerAliveInterval=2' \
  'ServerAliveCountMax=2'
grep -Fq 'local deadline="$((SECONDS + 60))"' "$LINUX_HOST_LIB" \
  || fail "Linux host runner wait does not outlive the guest Direct restoration deadline"
if grep -Fq 'LINUX_RUN_PID' "$LINUX_HOST" "$LINUX_HOST_LIB" \
  || grep -Fq 'reap_linux_guest_runner_if_exited' "$LINUX_HOST_LIB"
then
  fail "Linux gate still couples the guest runner to a long SSH process"
fi
require_tokens "$LINUX_HOST" "detached guest-runner lifecycle" \
  'realpath' \
  'LINUX_RUN_UNIT=' \
  'start_guest_secondary_unit run' \
  'wait_for_guest_runner_success' \
  'stop_guest_runner_unit'
require_tokens "$LINUX_HOST" "fail-closed runtime evidence capture" \
  'capture_guest_state secondary' \
  'capture_guest_state primary' \
  'guest_capture_required=' \
  'guest_capture_succeeded=1' \
  'peer_capture_required=' \
  'peer_capture_succeeded=1'
grep -Fq 'capture_failed=1' "$LINUX_HOST" \
  || fail "Linux evidence capture does not fail when required runtime evidence is missing"
if grep -Fq 'captured=1' "$LINUX_HOST"; then
  fail "Linux evidence capture can report success after a failed tar pipeline"
fi
if grep -Fq "tar --ignore-failed-read -C '\$GUEST_STATE_DIR' -cf - ." "$LINUX_HOST" \
  || grep -Fq "tar --ignore-failed-read -C '\$PEER_STATE_DIR' -cf - ." "$LINUX_HOST"
then
  fail "Linux failure artifacts can copy secret sidecars or raw configs"
fi
grep -Fq -- "-iname '*secret*' -o -name 'config.toml'" "$LINUX_HOST" \
  || fail "Linux artifact collection lacks a defensive secret/config exclusion"
if grep -Eq 'Copy-Item.+StateDir|Get-ChildItem.+StateDir' "$WINDOWS_HOST"; then
  fail "Windows failure artifacts can copy the raw state directory"
fi
grep -Fq 'last_route=' "$LINUX_GUEST" \
  || fail "Linux recovery failure omits its last route condition"
grep -Fq 'dump_recovery_failure' "$LINUX_GUEST" \
  || fail "Linux pre-receipt recovery failure does not surface daemon/network diagnostics"
if grep -Fq 'physical_default_route_dev' "$LINUX_GUEST"; then
  fail "Linux exit recovery incorrectly requires an absent physical default route"
fi
python3 - "$LINUX_GUEST" "$LINUX_HOST_ENTRY" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
ready = source[
    source.index("assert_secondary_underlay_ready() {"):
    source.index("\nrun_gate() {")
]
if 'route show table main default dev "$interface"' in ready:
    raise SystemExit(
        "Linux pre-cut readiness incorrectly requires a live physical default under strict exit"
    )
for token in (
    "previous_main_default_routes",
    "strict exit retained an unmanaged physical default before the host cut",
    "durable_default_route: true",
    'defaults_json="$(ip -j -4 route show table main default)"',
    "length >= 1 and all(.[]; .dev == $wireguard)",
):
    if token not in ready:
        raise SystemExit(
            f"Linux pre-cut readiness lacks strict-exit ownership evidence: {token}"
        )
endpoint_route = source[
    source.index("assert_wireguard_endpoint_route() {"):
    source.index("\nmonotonic_milliseconds() {")
]
if 'route show default dev "$expected_iface"' in endpoint_route:
    raise SystemExit(
        "Linux endpoint proof incorrectly derives its gateway from an absent physical default"
    )
for token in ("$CLEANUP_JOURNAL", "previous_main_default_routes"):
    if token not in endpoint_route:
        raise SystemExit(
            f"Linux endpoint proof lacks durable underlay ownership: {token}"
        )
for token in (
    'wireguard_endpoint_route_matches',
    'initial_last_predicate=',
    'ACTIVE_EXIT_LAST_PREDICATE=wireguard_endpoint_tuple',
    'ACTIVE_EXIT_LAST_PREDICATE=fixture_dns',
    'ACTIVE_EXIT_LAST_PREDICATE=public_dns',
    'ACTIVE_EXIT_LAST_PREDICATE=https',
    '(.tunnel_ip | split("/")[0]) == $tunnel_ip',
):
    if token not in source:
        raise SystemExit(
            f"Linux pre-cut readiness lacks focused failure observability: {token}"
        )
host = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
runner = host[
    host.index("start_linux_runner() {"):
    host.index("\nset_primary_link() {")
]
if ".default_route == true" in runner:
    raise SystemExit(
        "Linux host wrapper still requires a live physical default under strict exit"
    )
for token in (
    ".default_route == false",
    ".durable_default_route == true",
    ".strict_exit_physical_defaults_absent == true",
):
    if token not in runner:
        raise SystemExit(
            f"Linux host wrapper lacks strict-exit pre-cut evidence: {token}"
        )
PY
jq -en \
  --arg status_ip "10.44.0.2/32" \
  --arg identity_ip "10.44.0.2" \
  '($status_ip | split("/")[0]) == $identity_ip' >/dev/null \
  || fail "Linux daemon identity rejects equivalent CIDR and bare tunnel IPs"
route_matcher="$COMBINED_DIR/wireguard-endpoint-route-matches.sh"
sed -n \
  '/^wireguard_endpoint_route_matches() {$/,/^}$/p' \
  "$LINUX_GUEST" >"$route_matcher"
# shellcheck source=/dev/null
source "$route_matcher"
for dst in "203.0.113.10" "203.0.113.10/32"; do
  wireguard_endpoint_route_matches \
    "[{\"dst\":\"$dst\",\"dev\":\"eth0\",\"gateway\":\"192.0.2.1\",\"prefsrc\":\"192.0.2.10\"}]" \
    eth0 192.0.2.1 192.0.2.10 203.0.113.10 \
    || fail "Linux endpoint route rejected the valid $dst kernel spelling"
done
for invalid_route in \
  '[{"dst":"203.0.113.10","dev":"eth1","gateway":"192.0.2.1","prefsrc":"192.0.2.10"}]' \
  '[{"dst":"203.0.113.10","dev":"eth0","gateway":"192.0.2.2","prefsrc":"192.0.2.10"}]' \
  '[{"dst":"203.0.113.10","dev":"eth0","gateway":"192.0.2.1","prefsrc":"192.0.2.11"}]'
do
  if wireguard_endpoint_route_matches \
    "$invalid_route" eth0 192.0.2.1 192.0.2.10 203.0.113.10
  then
    fail "Linux endpoint route accepted a wrong ownership tuple"
  fi
done
recovery_contract="$COMBINED_DIR/linux-recovery-public-probe.sh"
sed -n \
  '/^assert_active_exit() {$/,/^}$/p; /^recovery_network_probe() ($/,/^)/p' \
  "$LINUX_GUEST" >"$recovery_contract"
require_tokens "$recovery_contract" "fresh concurrent recovery probe" \
  'local RECOVERY_STARTED_MS="$started"' \
  'resolve_fixture || return 1' \
  'resolve_name_without_flush "$(probe_host)" || return 1' \
  'test_https || return 1' \
  'https_at="$(monotonic_milliseconds)"' \
  'printf '\''%s\n'\'' "$https_at" >"$temporary"'
https_counter_line="$(grep -nF 'monotonic_milliseconds >>"$STATE_DIR/wireguard-payload.log"' \
  "$LINUX_GUEST" | cut -d: -f1)"
recovery_probe_launch_line="$(grep -nF 'recovery_network_probe "$network_probe_arm" "$network_probe_receipt" &' \
  "$LINUX_GUEST" | cut -d: -f1)"
recovery_cut_arm_line="$(grep -nF 'write_marker "armed-$label"' \
  "$LINUX_GUEST" | cut -d: -f1)"
recovery_route_line="$(grep -nF 'route_usable_monotonic="$(monotonic_milliseconds)"' \
  "$LINUX_GUEST" | cut -d: -f1)"
recovery_probe_arm_line="$(grep -nF 'printf '\''%s\n'\'' "$started" >"$network_probe_arm"' \
  "$LINUX_GUEST" | cut -d: -f1)"
recovery_evidence_line="$(grep -nF 'recovered_elapsed="$((recovered_monotonic - started))"' \
  "$LINUX_GUEST" | cut -d: -f1)"
recovery_audit_line="$(grep -nF 'assert_active_exit_state "$expected_iface" "$expected_pid"' \
  "$LINUX_GUEST" | tail -n 1 | cut -d: -f1)"
[[ -n "$https_counter_line" && -n "$recovery_probe_launch_line" \
  && -n "$recovery_cut_arm_line" && -n "$recovery_route_line" \
  && -n "$recovery_probe_arm_line" && -n "$recovery_evidence_line" \
  && -n "$recovery_audit_line" ]] \
  || fail "Linux recovery lacks pre-armed timestamped DNS/HTTPS evidence"
((https_counter_line < recovery_probe_launch_line \
  && recovery_probe_launch_line < recovery_cut_arm_line \
  && recovery_cut_arm_line < recovery_route_line \
  && recovery_route_line < recovery_probe_arm_line \
  && recovery_probe_arm_line < recovery_evidence_line \
  && recovery_evidence_line < recovery_audit_line)) \
  || fail "Linux recovery probe/evidence/stable-audit ordering is unsafe"
grep -Fq 'route_dev "$(endpoint_host)"' "$LINUX_GUEST" \
  || fail "Linux recovery clock does not wait for the physical endpoint route"
require_tokens "$LINUX_GUEST" "Linux independently timestamped recovery evidence" \
  'rebind_at="$now"' \
  'payload_at="$now"' \
  'wg_payload_at="$now"' \
  'read -r network_at <"$network_probe_receipt"' \
  'for evidence_at in \' \
  '((evidence_at > recovered_monotonic))' \
  'recovered_elapsed="$((recovered_monotonic - started))"' \
  '((recovered_elapsed <= RECOVERY_DEADLINE_MS))' \
  'deadline_edge_read=1' \
  'rebind_observed_monotonic_milliseconds' \
  'payload_success_observed_monotonic_milliseconds' \
  'wireguard_payload_success_monotonic_milliseconds' \
  'network_probe_success_monotonic_milliseconds'
require_tokens "$LINUX_GUEST" "Linux post-measurement stable-state audit" \
  'assert_same_daemon_ready "$expected_pid" || return 1' \
  'assert_wireguard_endpoint_route "$expected_iface" || return 1' \
  'wireguard_handshake_active || return 1' \
  'assert_secure_dns || return 1' \
  'resolve_fixture || return 1' \
  'resolve_name "$(probe_host)" || return 1' \
  'test_https || return 1'
grep -Fq 'stop_recovery_network_probe' "$LINUX_GUEST" \
  || fail "Linux cleanup does not stop the pre-armed recovery probe"
grep -Fq 'route_usable_monotonic_milliseconds' "$LINUX_HOST" \
  || fail "Linux host does not enforce the guest monotonic recovery receipt"
grep -Fq 'route_usable_monotonic_milliseconds' "$LINUX_GUEST" \
  || fail "Linux guest recovery does not use its own monotonic clock"
grep -Fq '10#$nanoseconds / 1000000' "$LINUX_GUEST" \
  || fail "Linux guest Unix-millisecond evidence is not portable across date implementations"
if grep -Fq 'date +%s%3N' "$LINUX_GUEST"; then
  fail "Linux guest relies on unsupported date field-width semantics for milliseconds"
fi
grep -Fq 'RECOVERY_DEADLINE_MS="${NVPN_UNDERLAY_RECOVERY_DEADLINE_MS:-4000}"' \
  "$LINUX_GUEST" \
  || fail "Linux guest changed the four-second product recovery bound"
[[ "$(grep -Fc 'assert_peer_recovered_from_source "$cut"' "$LINUX_HOST")" -eq 2 ]] \
  || fail "Linux peer evidence is not clocked from each hypervisor link cut"
for evidence in \
  '.wireguard_endpoint_route[0].dev == $interface' \
  '.wireguard_endpoint_route[0].gateway == $gateway' \
  '.wireguard_endpoint_route[0].prefsrc == $source'
do
  [[ "$(grep -Fc "$evidence" "$LINUX_HOST")" -eq 2 ]] \
    || fail "Linux host does not verify both complete endpoint-route tuples: $evidence"
done
for host_gate in "$WINDOWS_HOST" "$LINUX_HOST"; do
  if grep -Fq 'route_usable_unix_milliseconds / 1000' "$host_gate"; then
    fail "$(basename "$host_gate") compares guest and hypervisor wall clocks"
  fi
  grep -Fq 'expected_source_after_cut_seconds' "$host_gate" \
    || fail "$(basename "$host_gate") lacks same-clock expected-source timing"
  grep -Fq 'fips_expected_source_after_cut_seconds' "$host_gate" \
    || fail "$(basename "$host_gate") lacks physical FIPS source timing"
  grep -Fq 'wireguard_expected_source_after_cut_seconds' "$host_gate" \
    || fail "$(basename "$host_gate") lacks physical WireGuard source timing"
  grep -Fq 'reverse_payload_after_expected_source_seconds' "$host_gate" \
    || fail "$(basename "$host_gate") lacks same-clock reverse-payload timing"
  grep -Fq 'while :; do' "$host_gate" \
    || fail "$(basename "$host_gate") can skip already-recorded boundary evidence"
  require_tokens "$host_gate" "exact integer evidence bounds" \
    'fips_ns <= evidence_deadline_ns' \
    'wireguard_ns <= evidence_deadline_ns' \
    'reverse_ns <= evidence_deadline_ns' \
    'reverse_ns - fips_ns <= deadline_ns'
done
grep -Fq 'last_rebind_receipts=' "$LINUX_GUEST" \
  || fail "Linux recovery failure omits its rebind evidence"
require_tokens "$LINUX_GUEST" "pre-cut stable primary assertion" \
  '$(rebind_count) == 0' \
  'initial FIPS exit, DNS, HTTPS, and payload did not become ready'
require_tokens "$PEER" "pre-cut physical-source audit" \
  'initial-source-audit)' \
  'fips-underlay.pcap.txt' \
  'wireguard-underlay.pcap.txt' \
  'unexpected secondary-source traffic before the physical cut'
grep -Fq 'peer_command initial-source-audit' "$LINUX_HOST" \
  || fail "Linux host does not reject a self-induced underlay switch before the physical cut"
grep -Fq '172.31.253.1' "$WINDOWS_HOST" \
  || fail "Windows transient network has no isolated subnet"
grep -Fq '172.31.254.1' "$LINUX_HOST" \
  || fail "Linux transient network has no isolated subnet"

python3 - "$WINDOWS_HOST" "$WINDOWS_GUEST" "$LINUX_HOST" "$LINUX_GUEST" "$PEER" <<'PY'
import pathlib
import re
import sys

private = re.compile(
    r"\b(?:vader|win11-dev|ubuntu-dev|macos-utm)\b"
    r"|192\.168\.122\.[0-9]+"
    r"|/(?:Users|home)/[A-Za-z0-9._-]+/"
)
for name in sys.argv[1:]:
    text = pathlib.Path(name).read_text(encoding="utf-8")
    if match := private.search(text):
        raise SystemExit(
            f"{pathlib.Path(name).name} embeds private infrastructure near offset {match.start()}"
        )
PY

"$ROOT/scripts/test-desktop-underlay-peer-recovery-observer.sh"
echo "DESKTOP_UNDERLAY_NETWORK_CHANGE_SOURCE_CONTRACT_OK"
