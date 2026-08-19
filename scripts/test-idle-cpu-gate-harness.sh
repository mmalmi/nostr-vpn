#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/idle-cpu-gate.py"
RELEASE_GATE="$ROOT_DIR/scripts/release-gate.sh"
MOBILE_IOS_SMOKE="$ROOT_DIR/scripts/mobile-ios-smoke.sh"
MOBILE_ANDROID_SMOKE="$ROOT_DIR/scripts/mobile-android-smoke.sh"
MOBILE_WIREGUARD_EXIT="$ROOT_DIR/scripts/mobile-wireguard-exit-e2e.sh"

fail() {
  printf 'idle CPU gate harness failed: %s\n' "$*" >&2
  exit 1
}

assert_status() {
  local expected="$1"
  local label="$2"
  shift 2
  local out status
  out="$(mktemp)"
  set +e
  "$@" >"$out" 2>&1
  status=$?
  set -e
  if [[ "$status" != "$expected" ]]; then
    cat "$out" >&2 || true
    rm -f "$out"
    fail "$label returned $status, expected $expected"
  fi
  rm -f "$out"
}

assert_json_field() {
  local path="$1"
  local expression="$2"
  python3 - "$path" "$expression" <<'PY'
import json
import sys

path, expression = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)
if not eval(expression, {"__builtins__": {}}, {"data": data}):
    raise SystemExit(f"assertion failed: {expression}; data={data!r}")
PY
}

tmp_dir="$(mktemp -d)"
sleep_pid=""
busy_pid=""
cleanup() {
  if [[ -n "$sleep_pid" ]]; then
    kill "$sleep_pid" >/dev/null 2>&1 || true
    wait "$sleep_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$busy_pid" ]]; then
    kill "$busy_pid" >/dev/null 2>&1 || true
    wait "$busy_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

sleep 10 &
sleep_pid=$!
idle_json="$tmp_dir/idle.json"
assert_status 0 "idle sleep process" \
  "$SCRIPT" host-pid \
    --pid "$sleep_pid" \
    --label "sleep idle" \
    --artifact "$idle_json" \
    --settle-seconds 0 \
    --sample-seconds 0.2 \
    --max-percent 5
assert_json_field "$idle_json" 'data["ok"] is True and data["cpuPercent"] <= data["maxPercent"]'

python3 -c 'while True: pass' &
busy_pid=$!
busy_json="$tmp_dir/busy.json"
assert_status 1 "busy process" \
  "$SCRIPT" host-pid \
    --pid "$busy_pid" \
    --label "busy loop" \
    --artifact "$busy_json" \
    --settle-seconds 0 \
    --sample-seconds 0.4 \
    --max-percent 1
assert_json_field "$busy_json" 'data["ok"] is False and data["cpuPercent"] > data["maxPercent"]'

missing_json="$tmp_dir/missing.json"
assert_status 1 "missing process" \
  "$SCRIPT" host-pid \
    --pid 999999 \
    --label "missing process" \
    --artifact "$missing_json" \
    --settle-seconds 0 \
    --sample-seconds 0.1 \
    --max-percent 5
assert_json_field "$missing_json" 'data["ok"] is False and "error" in data'

fake_xcrun="$tmp_dir/xcrun"
cat >"$fake_xcrun" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
action="${2:-}"
input=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) input="$2"; shift ;;
    --output) output="$2"; shift ;;
  esac
  shift
done
if [[ "$action" == "record" ]]; then
  if [[ -n "${NVPN_FAKE_XCTRACE_SLEEP_SECONDS:-}" ]]; then
    sleep "$NVPN_FAKE_XCTRACE_SLEEP_SECONDS"
  fi
  mkdir -p "$output"
  exit 0
fi
cpu_ns=1000000000
if [[ "$input" == *end.trace ]]; then
  cpu_ns="${NVPN_FAKE_IOS_CPU_END_NS:-1002000000}"
fi
cat >"$output" <<XML
<trace-query-result><node><row><start-time/><process fmt="Nostr VPN Tunnel (42)"><pid>42</pid></process><event-time/><boolean/><pid/><process-uid/><duration-on-core>${cpu_ns}</duration-on-core></row></node></trace-query-result>
XML
SH
chmod +x "$fake_xcrun"

ios_json="$tmp_dir/ios.json"
assert_status 0 "idle iOS process" \
  "$SCRIPT" ios-process \
    --xcrun "$fake_xcrun" \
    --device test-phone \
    --process-pattern '^Nostr VPN Tunnel$' \
    --label "iOS packet tunnel" \
    --artifact "$ios_json" \
    --settle-seconds 0 \
    --sample-seconds 0.1 \
    --snapshot-seconds 0.1 \
    --max-percent 5
assert_json_field "$ios_json" 'data["ok"] is True and data["mode"] == "ios-process" and data["xctraceTimeoutSeconds"] == 20'

ios_busy_json="$tmp_dir/ios-busy.json"
assert_status 1 "busy iOS process" \
  env NVPN_FAKE_IOS_CPU_END_NS=1100000000 \
  "$SCRIPT" ios-process \
    --xcrun "$fake_xcrun" \
    --device test-phone \
    --process-pattern '^Nostr VPN Tunnel$' \
    --label "iOS packet tunnel" \
    --artifact "$ios_busy_json" \
    --settle-seconds 0 \
    --sample-seconds 0.1 \
    --snapshot-seconds 0.1 \
    --max-percent 5
assert_json_field "$ios_busy_json" 'data["ok"] is False and data["cpuPercent"] > 5'

ios_timeout_json="$tmp_dir/ios-timeout.json"
assert_status 1 "hung iOS xctrace process" \
  env NVPN_FAKE_XCTRACE_SLEEP_SECONDS=2 \
  "$SCRIPT" ios-process \
    --xcrun "$fake_xcrun" \
    --device test-phone \
    --process-pattern '^Nostr VPN Tunnel$' \
    --label "iOS packet tunnel" \
    --artifact "$ios_timeout_json" \
    --settle-seconds 0 \
    --sample-seconds 0.1 \
    --snapshot-seconds 0.1 \
    --xctrace-timeout-seconds 0.2 \
    --max-percent 5
assert_json_field "$ios_timeout_json" 'data["ok"] is False and "timed out" in data["error"]'

grep -Fq 'idle-cpu-gate.py" ios-process' "$MOBILE_IOS_SMOKE" \
  || fail "iOS physical-device smoke does not run the packet-tunnel idle CPU check"
grep -Fq 'local ios_smoke_command=(./scripts/mobile-ios-smoke.sh device)' "$RELEASE_GATE" \
  || fail "release gate does not construct the physical iOS packet-tunnel command safely"
grep -Fq 'ios_smoke_command+=(--install --create-network --vpn-cycle)' "$RELEASE_GATE" \
  || fail "release gate does not install and exercise the candidate iOS packet tunnel"
grep -Fq 'run_android_idle_cpu_gate "Android Release foreground VPN-off"' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android exact Release smoke does not measure foreground VPN-off idle CPU"
# shellcheck disable=SC2016 # Match the literal default-value contract.
grep -Fq 'ANDROID_RELEASE_FOREGROUND_IDLE_CPU_MAX_PERCENT="${NVPN_ANDROID_RELEASE_FOREGROUND_IDLE_CPU_MAX_PERCENT:-2}"' "$RELEASE_GATE" \
  || fail "release gate does not cap Android exact Release foreground idle CPU at 2 percent"
# shellcheck disable=SC2016 # Match the literal default-value contract.
grep -Fq 'ANDROID_RELEASE_FOREGROUND_IDLE_CPU_SAMPLE_SECONDS="${NVPN_ANDROID_RELEASE_FOREGROUND_IDLE_CPU_SAMPLE_SECONDS:-60}"' "$RELEASE_GATE" \
  || fail "release gate does not sample Android exact Release foreground idle CPU for 60 seconds"
grep -Fq 'Android Release foreground idle CPU gate requires VPN-off state' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android exact Release foreground idle gate does not require VPN-off state"
grep -Fq 'android-release-foreground-vpn-off-idle/idle-cpu.json' "$RELEASE_GATE" \
  || fail "Android exact Release foreground idle CPU lacks a distinct artifact path"
grep -Fq 'write_android_release_foreground_idle_receipt' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android exact Release foreground idle CPU lacks its source/artifact-bound receipt"
grep -Fq 'android_args=(--release-network-gate "${android_args[@]}")' "$MOBILE_WIREGUARD_EXIT" \
  || fail "real Android network lane does not use the exact signed nondebuggable Release app"
grep -Fq 'run_android_activity_lifecycle_gate' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android physical smoke does not verify Activity background/foreground survival"
if grep -Fq 'fi.siriusbusiness.nvpn.releasegate' "$RELEASE_GATE"; then
  fail "release gate still installs a parallel Android package"
fi
grep -Fq 'NVPN_ANDROID_DEBUG_RELEASE_SIGNING=1' "$RELEASE_GATE" \
  || fail "release gate canonical Android smoke is not signed for in-place replacement"
grep -Fq 'remove_stale_nvpn_packages' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android smoke does not remove stale parallel nVPN packages"
grep -Fq 'NVPN_ANDROID_IDLE_CPU_OUTPUT="$evidence_dir/android-release-foreground-vpn-off-idle/idle-cpu.json"' "$RELEASE_GATE" \
  || fail "real Android network lane does not retain foreground idle CPU evidence"
grep -Fq 'env NVPN_IDLE_CPU_GATE=0' "$RELEASE_GATE" \
  || fail "release gate repeats physical idle sampling inside the WireGuard exit smoke"
grep -Fq 'environmentVariable("NVPN_ANDROID_PACKAGE")' "$ROOT_DIR/android/app/build.gradle.kts" \
  || fail "Android Gradle application id cannot follow the smoke package override"
grep -Fq 'CANONICAL_PACKAGE_NAME="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android smoke does not define the canonical action namespace"
grep -Fq 'ACTION_PACKAGE_NAME="${NVPN_ANDROID_ACTION_PACKAGE:-$CANONICAL_PACKAGE_NAME}"' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android smoke action name incorrectly follows the overridable package id"
grep -Fq 'OwnerUid: $PACKAGE_UID' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android smoke VPN state is not scoped to the candidate package uid"
grep -Fq '$1 ~ /^emulator-/' "$MOBILE_ANDROID_SMOKE" \
  || fail "Android smoke does not prefer an isolated emulator over a physical device"
grep -Fq 'NVPN_IDLE_CPU_SAMPLE_SECONDS:-60' "$RELEASE_GATE" \
  || fail "release gate does not cover a full mDNS cadence in CPU samples"
grep -Fq 'NVPN_IDLE_CPU_SETTLE_SECONDS:-15' "$RELEASE_GATE" \
  || fail "release gate does not exclude the Android tunnel startup/probe tail before CPU sampling"
grep -Fq 'env NVPN_MACOS_RUST_PROFILE=release NVPN_MACOS_XCODE_CONFIGURATION=Release' "$RELEASE_GATE" \
  || fail "release gate does not measure an optimized macOS app candidate"
grep -Fq 'run_macos_daemon_idle_cpu_gate' "$RELEASE_GATE" \
  || fail "release gate does not run the macOS daemon idle CPU check"
grep -Fq 'NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU:-auto' "$RELEASE_GATE" \
  || fail "macOS daemon gate cannot distinguish root-capable CI from developer hosts"
if grep -Fq 'nvpn-install-test-daemon --help' "$RELEASE_GATE"; then
  fail "macOS daemon gate uses an invalid helper argument as a sudo probe"
fi
grep -Fq 'sudo -n "$NVPN_BIN" service install' "$ROOT_DIR/scripts/e2e-macos-service.sh" \
  || fail "macOS service E2E can block waiting for an interactive sudo password"
grep -Fq 'ios_smoke_command+=(--device "$ios_device")' "$RELEASE_GATE" \
  || fail "release gate does not allow the physical iOS idle gate to auto-select a device"
grep -Fq -- '--fips-peer-endpoint' "$ROOT_DIR/scripts/e2e-macos-service.sh" \
  || fail "macOS daemon idle CPU check does not exercise an active mesh fixture"
grep -Fq 'ps -ww -p "$daemon_pid"' "$ROOT_DIR/scripts/e2e-macos-service.sh" \
  || fail "macOS daemon identity check may truncate the launchd command"
grep -Fq 'os.path.realpath(sys.argv[1])' "$ROOT_DIR/scripts/e2e-macos-service.sh" \
  || fail "macOS daemon identity check does not account for launchd path canonicalization"
grep -Fq 'NVPN_MACOS_SWIFT_COMPILATION_MODE:-singlefile' "$ROOT_DIR/scripts/macos-build" \
  || fail "macOS release build does not avoid hosted whole-module Swift compiler failures"
grep -Fq 'NVPN_MACOS_SWIFT_ENABLE_BATCH_MODE:-NO' "$ROOT_DIR/scripts/macos-build" \
  || fail "macOS release build does not disable hosted Swift batch compilation"
grep -Fq 'NVPN_MACOS_XCODE_JOBS:-1' "$ROOT_DIR/scripts/macos-build" \
  || fail "macOS release build does not serialize hosted Xcode compilation"
grep -Fq 'NVPN_MACOS_SWIFTC_MAXIMUM_DETERMINISM:-1' "$ROOT_DIR/scripts/macos-build" \
  || fail "macOS release build does not serialize Swift driver jobs"
grep -Fq 'build >&2' "$ROOT_DIR/scripts/macos-build" \
  || fail "macOS release build can discard Xcode diagnostics"
grep -Fq 'docker exec "$container_name" test -f /tmp/nostr-vpn-dev-ready' "$ROOT_DIR/tools/run-linux" \
  || fail "Linux runner readiness does not use the direct initialized-container probe"
grep -Fq '"${container_exec[@]}" "$container_name" /usr/local/bin/dev-entrypoint "$@"' "$ROOT_DIR/tools/run-linux" \
  || fail "Linux runner command still depends on the wedged Compose exec path"
grep -Fq 'docker compose logs --no-color --tail 200 nostr-vpn-linux' "$ROOT_DIR/tools/run-linux" \
  || fail "Linux runner does not preserve early container failure diagnostics"
grep -Fq 'NVPN_LINUX_NONINTERACTIVE=1' "$RELEASE_GATE" \
  || fail "release gate can allocate an interactive Docker exec and wedge the Linux GUI smoke"
grep -Fq 'NVPN_LINUX_NONINTERACTIVE:-0' "$ROOT_DIR/tools/run-linux" \
  || fail "Linux runner cannot force a non-interactive Docker exec from a terminal"
grep -Fq 'assert_idle_daemon_cpu_below node-a' "$ROOT_DIR/scripts/e2e-fips-routed-udp-docker.sh" \
  || fail "release-gated Linux active-tunnel e2e has no daemon idle CPU check"
grep -Fq 'NVPN_LINUX_DAEMON_IDLE_CPU_MAX_PERCENT="${NVPN_LINUX_DAEMON_IDLE_CPU_MAX_PERCENT:-3}"' "$RELEASE_GATE" \
  || fail "release-gated Linux active-tunnel CPU ceiling is not calibrated for direct-path renegotiation"
grep -Fq 'RUST_LOG="${NVPN_E2E_RUST_LOG:-warn,nostr_relay_pool=off,boringtun::noise::timers=error}"' "$ROOT_DIR/scripts/e2e-fips-routed-udp-docker.sh" \
  || fail "release-gated Linux idle CPU does not use the shipped warning-level log default"
grep -Fq 'windows-daemon-idle-cpu.ps1' "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh" \
  || fail "release-gated Windows VM smoke has no daemon idle CPU check"
grep -Fq 'SSH_JUMP="${NVPN_WINDOWS_SSH_JUMP:-}"' "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh" \
  || fail "Windows VM app smoke cannot traverse the configured VM host"
grep -Fq 'windows_ssh_command "$host"' "$RELEASE_GATE" \
  || fail "release gate Windows reachability checks ignore the configured VM host"
grep -Fq 'Remove-Item -Force \$installer' "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh" \
  || fail "Windows VM smoke can reuse a stale installer after a failed build"
grep -Fq '\$env:CARGO_TARGET_DIR = Join-Path' "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh" \
  || fail "Windows VM smoke can rebuild binaries that its management service still locks"
grep -Fq "'windows-smoke-cargo'" "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh" \
  || fail "Windows VM smoke discards its Cargo cache on every gate"
grep -Fq 'Get-CimInstance Win32_Process' "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh" \
  || fail "Windows VM smoke does not stop a stale candidate before rebuilding its stable cache"
python3 - "$ROOT_DIR/scripts/local-release.mjs" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = text.index("function buildWindowsArtifacts(")
end = text.index("\nfunction buildLinuxArtifacts(", start)
windows = text[start:end]
for required in (
    "validateWindowsInstallerGateReceipt({",
    "NVPN_WINDOWS_RELEASE_ARCHIVE_PATH",
    "exactRegularFile(retainedArchivePath",
    "Reused the exact Windows installer and CLI payload exercised by the Windows VM gate.",
):
    if required not in windows:
        raise SystemExit(
            f"Windows publication does not reuse its exact VM-gated payload: {required}"
        )
for forbidden in (
    "cargo build",
    "windows-build.ps1",
    "runWindowsPowerShell",
    "pullFileFromWindowsHost",
):
    if forbidden in windows:
        raise SystemExit(
            f"Windows publication can rebuild a payload held by the VM gate: {forbidden}"
        )
PY
grep -Fq 'NVPN_WINDOWS_SKIP_GIT_SYNC' "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh" \
  || fail "Windows VM app smoke cannot reuse a release-gate candidate sync"
for exact_fips_token in \
  'NVPN_FIPS_REPO_PATH' \
  'fipsGitSha' \
  'fipsGitTree' \
  'version --verbose' \
  'Windows installer payload does not embed the exact FIPS revision'
do
  grep -Fq "$exact_fips_token" "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh" \
    || fail "Windows VM app smoke lacks exact FIPS provenance: $exact_fips_token"
done
grep -Fq 'NVPN_WINDOWS_SKIP_GIT_SYNC' "$ROOT_DIR/scripts/windows-vm-wireguard-exit-e2e.sh" \
  || fail "Windows WG smoke cannot reuse a release-gate candidate sync"
if [[ "$(grep -Fc 'if (\$LASTEXITCODE -ne 0)' "$ROOT_DIR/scripts/windows-vm-app-launch-smoke.sh")" -lt 3 ]]; then
  fail "Windows VM smoke ignores a nested build, installer, or daemon check failure"
fi
grep -Fq 'Get-UsableHostIPv4' "$ROOT_DIR/scripts/windows-daemon-idle-cpu.ps1" \
  || fail "Windows daemon idle CPU fixture does not discover a usable host address"
if grep -F -- '--fips-peer-endpoint' "$ROOT_DIR/scripts/windows-daemon-idle-cpu.ps1" | grep -Fq '127.0.0.1'; then
  fail "Windows daemon idle CPU fixture advertises a rejected loopback peer endpoint"
fi
grep -Fq 'if ($LASTEXITCODE -ne 0)' "$ROOT_DIR/scripts/windows-daemon-idle-cpu.ps1" \
  || fail "Windows daemon idle CPU fixture ignores native nvpn command failures"
grep -Fq "'--iface', 'nvpn-idle-cpu'" "$ROOT_DIR/scripts/windows-daemon-idle-cpu.ps1" \
  || fail "Windows daemon idle CPU fixture can collide with the installed tunnel interface"
grep -Fq '"NVPN_IDLE_CPU_SAMPLE_SECONDS" 60' "$ROOT_DIR/scripts/windows-app-launch-smoke.ps1" \
  || fail "Windows app idle CPU gate does not sample a full minute"
grep -Fq '"NVPN_IDLE_CPU_SETTLE_SECONDS" 20' "$ROOT_DIR/scripts/windows-app-launch-smoke.ps1" \
  || fail "Windows app idle CPU gate does not exclude startup warm-up"

printf 'idle CPU gate harness passed\n'
