#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-cleanup-test.XXXXXX")"
trap 'rm -rf "$FIXTURE"' EXIT
mkdir -p "$FIXTURE/bin"

fail() {
  printf 'iOS VPN cleanup harness failed: %s\n' "$*" >&2
  exit 1
}

cat >"$FIXTURE/bin/xcrun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
rendered="$*"
if [[ "$rendered" == *"device process launch"*"--payload-url"* ]]; then
  payload_url=""
  previous=""
  for argument in "$@"; do
    if [[ "$previous" == "--payload-url" ]]; then
      payload_url="$argument"
      break
    fi
    previous="$argument"
  done
  decoded="$(python3 - "$payload_url" <<'PY'
import base64
import json
import sys
from urllib.parse import parse_qs, urlparse

encoded = parse_qs(urlparse(sys.argv[1]).query)["arguments"][0]
encoded += "=" * (-len(encoded) % 4)
print(" ".join(json.loads(base64.urlsafe_b64decode(encoded))))
PY
)"
  rendered="$rendered $decoded"
fi
printf '%s\n' "$rendered" >>"$NVPN_TEST_XCRUN_LOG"
if [[ "$rendered" == "devicectl device info details"* ]]; then
  destination=""
  previous=""
  for argument in "$@"; do
    if [[ "$previous" == "--json-output" ]]; then
      destination="$argument"
      break
    fi
    previous="$argument"
  done
  if [[ -n "$destination" ]]; then
    printf '{"result":{"hardwareProperties":{"udid":"test-hardware-udid"}}}\n' \
      >"$destination"
  fi
  exit 0
fi
if [[ "$rendered" == "devicectl device info lockState"* ]]; then
  destination=""
  previous=""
  for argument in "$@"; do
    if [[ "$previous" == "--json-output" ]]; then
      destination="$argument"
      break
    fi
    previous="$argument"
  done
  if [[ "${NVPN_TEST_DEVICE_LOCKED:-0}" == "1" ]]; then
    printf '{"result":{"passcodeRequired":true,"unlockedSinceBoot":true}}\n' \
      >"$destination"
  else
    printf '{"result":{"passcodeRequired":false,"unlockedSinceBoot":true}}\n' \
      >"$destination"
  fi
  exit 0
fi
if [[ "$rendered" == "devicectl device info apps"* ]]; then
  [[ "${NVPN_TEST_APP_INSTALLED:-0}" == "1" ]] \
    && printf 'Nostr VPN fi.siriusbusiness.nvpn 4.1.4 4001004\n'
  exit 0
fi
if [[ "$rendered" == *"device process launch"*"--nvpn-debug-disconnect-result"* ]]; then
  [[ "${NVPN_TEST_DISCONNECT_LAUNCH_FAIL:-0}" == "1" ]] && exit 74
  exit 0
fi
if [[ "$rendered" == *"device process launch"*"--nvpn-debug-exit-probe"* ]]; then
  exit 0
fi
if [[ "$rendered" == *"device copy from"*"mobile-ios-disconnect-"* ]]; then
  destination="${@: -2:1}"
  printf '{"ok":true,"packetTunnelStatusRawValue":1}\n' >"$destination"
  exit 0
fi
if [[ "$rendered" == *"device copy from"* ]]; then
  exit 75
fi
exit 0
EOF
chmod +x "$FIXTURE/bin/xcrun"

cat >"$FIXTURE/bin/uname" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-s" ]]; then
  printf 'Darwin\n'
  exit 0
fi
exec /usr/bin/uname "$@"
EOF
chmod +x "$FIXTURE/bin/uname"

COMMON_ENV=(
  PATH="$FIXTURE/bin:$PATH"
  NVPN_IOS_DEVICE=test-device
  NVPN_IOS_TEAM_ID=test-team
  NVPN_IOS_DEVICE_SIGNING_MODE=development
  NVPN_IOS_VPN_START_WAIT_SECS=0
  NVPN_IOS_VPN_RESULT_WAIT_SECS=0
  NVPN_IOS_LIFECYCLE_GATE=0
  NVPN_IDLE_CPU_GATE=0
  NVPN_TEST_XCRUN_LOG="$FIXTURE/xcrun.log"
)

resolved_udid="$(
  env PATH="$FIXTURE/bin:$PATH" NVPN_TEST_XCRUN_LOG="$FIXTURE/xcrun.log" \
    bash -c "source '$ROOT/scripts/mobile_env.sh'; resolve_physical_ios_udid test-device"
)"
[[ "$resolved_udid" == "test-hardware-udid" ]] \
  || fail "physical iOS name did not resolve to its hardware UDID"

env PATH="$FIXTURE/bin:$PATH" NVPN_TEST_XCRUN_LOG="$FIXTURE/xcrun.log" \
  bash -c \
    "source '$ROOT/scripts/lib-mobile-ios-release-network.sh'; ios_release_network_require_unlocked test-device" \
  || fail "unlocked physical iOS device was rejected"

watchdog_marker="$FIXTURE/watchdog-active"
touch "$watchdog_marker"
watchdog_started=$SECONDS
env PATH="$FIXTURE/bin:$PATH" bash -c \
  "source '$ROOT/scripts/lib-mobile-ios-release-network.sh'; ios_release_network_cleanup_watchdog '$watchdog_marker' 999999 30 5" &
watchdog_pid=$!
sleep 0.2
rm -f "$watchdog_marker"
wait "$watchdog_pid" || fail "cancelled cleanup watchdog failed"
((SECONDS - watchdog_started < 2)) \
  || fail "cancelled cleanup watchdog waited for its full deadline"
set +e
env PATH="$FIXTURE/bin:$PATH" \
  NVPN_TEST_XCRUN_LOG="$FIXTURE/xcrun.log" \
  NVPN_TEST_DEVICE_LOCKED=1 \
  bash -c \
    "source '$ROOT/scripts/lib-mobile-ios-release-network.sh'; ios_release_network_require_unlocked test-device" \
  >"$FIXTURE/locked.out" 2>&1
status=$?
set -e
[[ "$status" -ne 0 ]] || fail "locked physical iOS device was accepted"
grep -Fq 'requires the selected phone to be unlocked' "$FIXTURE/locked.out" \
  || fail "locked physical iOS failure was not actionable"

set +e
env "${COMMON_ENV[@]}" "$ROOT/scripts/mobile-ios-smoke.sh" device --vpn-cycle \
  >"$FIXTURE/failure.out" 2>&1
status=$?
set -e
[[ "$status" -ne 0 ]] || fail "failed probe unexpectedly passed"
grep -Fq -- '--nvpn-debug-exit-probe' "$FIXTURE/xcrun.log" \
  || fail "fixture did not start the test tunnel"
grep -Fq -- '--nvpn-debug-disconnect-result' "$FIXTURE/xcrun.log" \
  || fail "failed probe did not run emergency disconnect"
grep -Fq 'iOS VPN cleanup verified: packet tunnel is disconnected' "$FIXTURE/failure.out" \
  || fail "failed probe did not verify emergency disconnect"
if awk '/device process launch/ && $0 !~ /--activate/ { found = 1 } END { exit !found }' \
  "$FIXTURE/xcrun.log"
then
  fail "physical iOS automation launched the app without foregrounding it"
fi

: >"$FIXTURE/xcrun.log"
set +e
env "${COMMON_ENV[@]}" \
  NVPN_TEST_APP_INSTALLED=1 \
  NVPN_TEST_DISCONNECT_LAUNCH_FAIL=1 \
  NVPN_IOS_INSTALL=1 \
  "$ROOT/scripts/mobile-ios-smoke.sh" device --install \
  >"$FIXTURE/install.out" 2>&1
status=$?
set -e
[[ "$status" -ne 0 ]] || fail "unsafe replacement unexpectedly passed"
grep -Fq 'Refusing to replace fi.siriusbusiness.nvpn' "$FIXTURE/install.out" \
  || fail "unsafe replacement did not report its guard"
if grep -Fq 'device install app' "$FIXTURE/xcrun.log"; then
  fail "unsafe replacement reached the install command"
fi

if grep -Eq -- '--domain-type appGroupDataContainer|NVPN_IOS_ALLOW_LEGACY_APP_DATA_CLEANUP' \
  "$ROOT/scripts/mobile-ios-smoke.sh"
then
  fail "physical iOS gates retain a broken CoreDevice App Group copy or legacy receipt path"
fi
grep -Fq 'DEVICE_SIGNING_MODE="${NVPN_IOS_DEVICE_SIGNING_MODE:-adhoc}"' \
  "$ROOT/scripts/mobile-ios-smoke.sh" \
  || fail "physical iOS gates do not default to company Ad Hoc signing"
if grep -Fq 'mode="auto"' "$ROOT/scripts/mobile-ios-smoke.sh"; then
  fail "physical iOS signing still has an implicit development-signing mode"
fi
if grep -Eq -- '--terminate-existing' \
  "$ROOT/scripts/mobile_env.sh" \
  "$ROOT/scripts/mobile-ios-smoke.sh" \
  "$ROOT/scripts/lib-mobile-ios-lifecycle.sh" \
  "$ROOT/scripts/lib-mobile-ios-release-network.sh"
then
  fail "physical iOS automation can terminate the embedded packet tunnel"
fi
grep -Fq 'terminate_ios_app_processes_before_install "$device"' \
  "$ROOT/scripts/mobile-ios-smoke.sh" \
  || fail "safe iOS replacement can leave a stale UI process running"
grep -Fq 'ios_packet_tunnel_process_is_stopped "$device"' \
  "$ROOT/scripts/mobile-ios-smoke.sh" \
  || fail "safe iOS replacement cannot recover when an idle phone suspends its app"
grep -Fq '/Nostr VPN.app/PlugIns/Nostr VPN Tunnel.appex/Nostr VPN Tunnel' \
  "$ROOT/scripts/mobile-ios-smoke.sh" \
  || fail "safe iOS replacement does not identify the exact packet-tunnel process"
grep -Fq 'device process terminate' "$ROOT/scripts/mobile-ios-smoke.sh" \
  || fail "safe iOS replacement does not terminate the confirmed-idle UI process"
grep -Fq -- '--payload-url "nvpn://debug/automation?arguments=$encoded_arguments"' \
  "$ROOT/scripts/mobile_env.sh" \
  || fail "physical iOS automation does not use the non-terminating URL command channel"
grep -Fq 'resolve_physical_ios_udid' "$ROOT/scripts/mobile-ios-smoke.sh" \
  || fail "physical Xcode driver does not resolve CoreDevice names"
grep -Fq -- '-collect-test-diagnostics never' "$ROOT/scripts/mobile-ios-smoke.sh" \
  || fail "physical Xcode failure can stall on privileged diagnostics"
grep -Fq 'com.apple.Preferences' "$ROOT/scripts/lib-mobile-ios-lifecycle.sh" \
  || fail "physical lifecycle gate does not background through a real device app switch"
if grep -Eq 'xcodebuild|XCTest' "$ROOT/scripts/lib-mobile-ios-lifecycle.sh"; then
  fail "physical lifecycle gate still depends on fragile XCTest automation startup"
fi
grep -Fq 'udid = hardware.get("udid")' \
  "$ROOT/scripts/lib-mobile-ios-release-network.sh" \
  && grep -Fq 'print(udid)' "$ROOT/scripts/lib-mobile-ios-release-network.sh" \
  || fail "Release network gate does not resolve its selected CoreDevice hardware ID"
grep -Fq -- '-collect-test-diagnostics never' \
  "$ROOT/scripts/lib-mobile-ios-release-network.sh" \
  || fail "Release network gate can stall on privileged Xcode diagnostics"
grep -Fq 'source "$ROOT/scripts/lib-mobile-ios-release-network.sh"' \
  "$ROOT/scripts/mobile-wireguard-exit-e2e.sh" \
  || fail "mobile WireGuard gate bypasses the audited Release iOS driver"

python3 - "$ROOT/ios/UITests/NostrVpnReleaseNetworkUITests.swift" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
lifecycle = source.split("func testReleaseNetworkLifecycle() throws {", 1)[1].split(
    "func testReleaseDisconnectCleanup() throws {", 1
)[0]
teardown_blocks = lifecycle.split("addTeardownBlock", 2)
if len(teardown_blocks) != 3:
    raise SystemExit("Release XCTest has no dedicated VPN-off teardown")
if lifecycle.count("try self.turnVPNOffIfNeeded()") != 1:
    raise SystemExit("Release XCTest teardown bypasses the shipped VPN-off UI")
cleanup_guard = lifecycle.index(
    "guard let self, self.shippedUIVPNOffCleanupArmed else { return }"
)
activate = lifecycle.index("self.app.activate()", cleanup_guard)
foreground = lifecycle.index(
    "self.waitForApplicationState(.runningForeground, timeout: 10)",
    activate,
)
cleanup_disconnect = lifecycle.index("try self.turnVPNOffIfNeeded()", foreground)
if not cleanup_guard < activate < foreground < cleanup_disconnect:
    raise SystemExit("Release XCTest teardown does not foreground before VPN off")
arm = lifecycle.index("shippedUIVPNOffCleanupArmed = true")
stress = lifecycle.index("try driveRapidStartStopStress(")
connect = lifecycle.index("try turnVPNOn()")
normal_disconnect = lifecycle.rindex("try turnVPNOffIfNeeded()")
disarm = lifecycle.index("shippedUIVPNOffCleanupArmed = false", normal_disconnect)
if not arm < stress < connect < normal_disconnect < disarm:
    raise SystemExit("Release XCTest VPN-off teardown has unsafe arm/disarm ordering")
if "shippedUIVPNOffCleanupArmed = false" in lifecycle[arm:normal_disconnect]:
    raise SystemExit("mid-test failure could disarm the VPN-off teardown")
PY

python3 - \
  "$ROOT/ios/Sources/AppModel.swift" \
  "$ROOT/ios/Sources/PacketTunnelController.swift" \
  "$ROOT/ios/Sources/AppModelDebugAutomation.swift" \
  "$ROOT/ios/Sources/AppModelSupport.swift" \
  "$ROOT/ios/PacketTunnel/PacketTunnelProvider.swift" \
  "$ROOT/scripts/ios-profiles" \
  "$ROOT/ios/Sources/AppModelDebugURLAutomation.swift" \
  "$ROOT/ios/Sources/AppModelDebugLifecycle.swift" \
  "$ROOT/ios/Sources/NostrVpnIosApp.swift" \
  "$ROOT/scripts/lib-mobile-ios-lifecycle.sh" \
  "$ROOT/scripts/release-gate.sh" <<'PY'
import sys

app_model = open(sys.argv[1], encoding="utf-8").read()
controller = open(sys.argv[2], encoding="utf-8").read()
automation = open(sys.argv[3], encoding="utf-8").read()
app_support = open(sys.argv[4], encoding="utf-8").read()
packet_tunnel = open(sys.argv[5], encoding="utf-8").read()
profiles = open(sys.argv[6], encoding="utf-8").read()
url_automation = open(sys.argv[7], encoding="utf-8").read()
lifecycle_automation = open(sys.argv[8], encoding="utf-8").read()
ios_app = open(sys.argv[9], encoding="utf-8").read()
lifecycle_gate = open(sys.argv[10], encoding="utf-8").read()
release_gate = open(sys.argv[11], encoding="utf-8").read()
if "throw PacketTunnelControllerError.disconnectTimedOut(status)" not in controller:
    raise SystemExit("disconnect timeout does not fail closed")
start_method = controller.split("func start(", 1)[1].split("static func routeState", 1)[0]
disconnect_index = start_method.index("try await stopAndWaitForDisconnected(manager)")
phase_index = start_method.index("await onActiveTunnelDisconnected?()")
save_index = start_method.index("try await save(manager,")
if not save_index < disconnect_index < phase_index:
    raise SystemExit("PacketTunnel replacement can stop before its new preferences are durable")
if "Task {" not in start_method or "try await update.value" not in start_method:
    raise SystemExit("PacketTunnel preference replacement is cancellable mid-transaction")
if "let (manager, managerIsNew) = try await loadOrCreateManager()" not in start_method:
    raise SystemExit("PacketTunnel start does not identify the first interactive manager save")
if "try await save(manager, waitsForUserApproval: managerIsNew)" not in start_method:
    raise SystemExit("PacketTunnel start does not preserve the first approval attempt")
save_helper = controller.split("private func save(", 1)[1].split(
    "private func reload", 1
)[0]
if "waitsForUserApproval ? nil : Self.preferencesOperationTimeoutSeconds" not in save_helper:
    raise SystemExit("first interactive VPN approval still has a hard preference timeout")
reload_helper = controller.split("private func reload(", 1)[1].split(
    "private func withPreferencesCompletion", 1
)[0]
if "timeoutSeconds: Self.preferencesOperationTimeoutSeconds" not in reload_helper:
    raise SystemExit("noninteractive VPN preference reload lost its bounded timeout")
disconnect_helper = controller.split(
    "private func stopAndWaitForDisconnected(", 1
)[1].split("private func waitForDisconnected", 1)[0]
if "manager.connection.stopVPNTunnel()" not in disconnect_helper:
    raise SystemExit("PacketTunnel replacement cannot stop the active tunnel")
if "return try await waitForDisconnected(manager)" not in disconnect_helper:
    raise SystemExit("PacketTunnel replacement does not confirm disconnect")
debug_start = automation.split("private func startVpnForDebugProbe()", 1)[1].split(
    "private func fetchDebugProbe", 1
)[0]
debug_native_enable = debug_start.index("dispatch(NativeActions.connectVpn())")
debug_serialized_config = debug_start.index("let tunnelConfigJson = core.mobileTunnelConfigJson()")
if debug_native_enable >= debug_serialized_config:
    raise SystemExit("physical iOS probe still serializes disabled native state")
if "--nvpn-debug-connect-result" not in automation or "status == 3" not in automation:
    raise SystemExit("physical iOS probe does not produce a confirmed-connect result")
if '?? "group.' in app_model or '?? "group.' in packet_tunnel:
    raise SystemExit("iOS target still silently falls back to an unrelated App Group")
if "migrateLegacySupportDirectoryIfNeeded" not in app_support:
    raise SystemExit("iOS App Group rollout does not migrate existing app state")
if "for: .applicationSupportDirectory" not in app_support:
    raise SystemExit("iOS App Group migration does not inspect the legacy app container")
if '"[[networks]]"' not in app_support:
    raise SystemExit("iOS App Group migration cannot replace an empty seeded config")
if 'legacy-private-container-migrated' not in app_support:
    raise SystemExit("iOS App Group migration has no durable one-time marker")
if "debugResultsDirectory" not in automation:
    raise SystemExit("iOS debug receipts do not have a private-container bridge")
if "--nvpn-debug-export-support-file" not in automation:
    raise SystemExit("iOS App Group support files cannot be exported for physical diagnostics")
if 'unavailable.error = "Shared app storage setup failed:' not in app_model:
    raise SystemExit("iOS App Group setup failures remain silent")
if "iosDebugLogLimitBytes" not in app_support or "moveItem(at: logURL" not in app_support:
    raise SystemExit("iOS app diagnostic log is not bounded")
if "packetDebugLogLimitBytes" not in packet_tunnel or "moveItem(at: logUrl" not in packet_tunnel:
    raise SystemExit("iOS packet-tunnel diagnostic log is not bounded")
if "verify_profile_app_group" not in profiles or "com.apple.security.application-groups" not in profiles:
    raise SystemExit("iOS provisioning profiles are not checked for the requested App Group")
if "plistlib.loads(sys.stdin.buffer.read())" not in profiles:
    raise SystemExit("iOS profile verification assumes seekable piped input")
if 'action == "automation"' not in app_model:
    raise SystemExit("iOS app does not receive physical automation without a process restart")
if "debugArguments(fromBase64URL" not in url_automation:
    raise SystemExit("iOS physical automation URL arguments are not explicitly decoded")
if "@Environment(\\.scenePhase)" not in ios_app or "model.handleScenePhase(phase)" not in ios_app:
    raise SystemExit("iOS app does not forward background/foreground lifecycle changes")
if "case .background:" not in app_model or "suspendNativeCore()" not in app_model:
    raise SystemExit("iOS app does not close its shared native core before suspension")
if "case .active:" not in app_model or "resumeNativeCore()" not in app_model:
    raise SystemExit("iOS app does not reopen its native core after foregrounding")
suspend = app_model.split("private func suspendNativeCore()", 1)[1].split("private func resumeNativeCore()", 1)[0]
if not all(token in suspend for token in ("pendingVpnTransitionEnabled != nil", "packetTunnelTransitionTask != nil", "if !preservePendingVpnTransition {", "tunnelConfigSyncTask?.cancel()", "startupTunnelReconciliationTask?.cancel()")):
    raise SystemExit("iOS backgrounding can cancel the delayed first-approval VPN start")
start = app_model.split("func start()", 1)[1].split("func handleScenePhase", 1)[0]
if "packetTunnelTransitionTask == nil" not in start:
    raise SystemExit("iOS foregrounding can enqueue a duplicate pending VPN transition")
if "pendingOpenURLs.append(url)" not in app_model:
    raise SystemExit("iOS deep links are not queued while the scene is inactive")
active_phase = app_model.split("case .active:", 1)[1].split("case .inactive:", 1)[0]
if "drainPendingOpenURLs()" not in active_phase:
    raise SystemExit("iOS foregrounding does not drain queued deep links")
handle_url = app_model.split("func handle(url: URL)", 1)[1].split(
    "private func drainPendingOpenURLs", 1
)[0]
if "resumeNativeCore()" in handle_url:
    raise SystemExit("iOS URL delivery can reopen the native core while backgrounded")
if ".onChange(of: scenePhase, initial: true)" not in ios_app:
    raise SystemExit("iOS initial active phase is not delivered to AppModel")
if "core?.close()" not in app_model or "core = nil" not in app_model:
    raise SystemExit("iOS suspension path can retain the shared Cashu wallet lock")
if "--nvpn-debug-lifecycle-result" not in lifecycle_automation:
    raise SystemExit("iOS physical build cannot report native-core lifecycle state")
debug_add_network = automation.split("private func addDebugNetworkIfPresent", 1)[1].split(
    "private func exportDebugSupportFileIfRequested", 1
)[0]
if "tunnelConfigSyncTask?.cancel()" not in debug_add_network:
    raise SystemExit("debug network setup can race its own single tunnel start")
if 'ios_lifecycle_activate "$device" "com.apple.Preferences"' not in lifecycle_gate:
    raise SystemExit("physical lifecycle gate does not physically background the app")
if 'ios_lifecycle_activate "$device" "$bundle_id"' not in lifecycle_gate:
    raise SystemExit("physical lifecycle gate does not physically foreground the app")
if 'sleep "$background_dwell"' not in lifecycle_gate:
    raise SystemExit("physical lifecycle gate omits the suspended dwell")
if 'ios_lifecycle_wait_for_active_tunnel_ready' not in lifecycle_gate:
    raise SystemExit("active-tunnel lifecycle can background before its observer is ready")
if "xcodebuild" in lifecycle_gate or "XCTest" in lifecycle_gate:
    raise SystemExit("physical lifecycle gate still depends on UI Automation")
if "ios_lifecycle_validate_history" not in lifecycle_gate:
    raise SystemExit("physical lifecycle gate does not validate app-side transition history")
if '"history": lifecycleProbeHistory' not in lifecycle_automation:
    raise SystemExit("iOS lifecycle receipt can still overwrite a brief background transition")
for timestamp in ("wallClockMilliseconds", "monotonicMilliseconds"):
    if timestamp not in lifecycle_automation:
        raise SystemExit(f"iOS lifecycle history omits {timestamp}")
if 'IOS_LIFECYCLE_GATE="${NVPN_IOS_LIFECYCLE_GATE:-1}"' not in open(
    sys.argv[1].replace("ios/Sources/AppModel.swift", "scripts/mobile-ios-smoke.sh"),
    encoding="utf-8",
).read():
    raise SystemExit("physical iOS lifecycle gate is not enabled by default")
if "run_mobile_idle_cpu_gates" not in release_gate:
    raise SystemExit("release gate no longer reaches the physical iOS smoke")
ios_smoke = open(
    sys.argv[1].replace("ios/Sources/AppModel.swift", "scripts/mobile-ios-smoke.sh"),
    encoding="utf-8",
).read()
mobile_env = open(
    sys.argv[1].replace("ios/Sources/AppModel.swift", "scripts/mobile_env.sh"),
    encoding="utf-8",
).read()
if 'get("hardwareProperties", {}).get("udid")' not in mobile_env:
    raise SystemExit("iOS signing does not resolve the exact selected device UDID")
if 'printf \'%s\\n\' "$NVPN_IOS_DEVICE_UDID"' in ios_smoke + mobile_env:
    raise SystemExit("iOS signing can still trust a stale unrelated device UDID")
PY

printf 'iOS VPN cleanup harness passed\n'
