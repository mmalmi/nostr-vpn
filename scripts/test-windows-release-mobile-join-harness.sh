#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XAML="$ROOT/windows/NostrVpn.Windows/MainWindow.xaml"
MODELS="$ROOT/windows/NostrVpn.Windows/Core/Models.cs"
VIEW_MODEL="$ROOT/windows/NostrVpn.Windows/ViewModels/AppViewModel.cs"
NATIVE_CALL_GATE="$ROOT/windows/NostrVpn.Windows/ViewModels/NativeCoreCallGate.cs"
ENROLLMENT="$ROOT/windows/NostrVpn.Windows/ViewModels/AppViewModel.Enrollment.cs"
DRIVER="$ROOT/scripts/desktop-mobile-manual-join-windows-ui.ps1"
REMOTE="$ROOT/scripts/windows-release-mobile-join-remote.ps1"
HOST="$ROOT/scripts/windows-vm-release-mobile-join-e2e.sh"

fail() {
  echo "Windows/Pixel release join harness failed: $*" >&2
  exit 1
}

for file in "$XAML" "$MODELS" "$VIEW_MODEL" "$NATIVE_CALL_GATE" "$ENROLLMENT" "$DRIVER" "$REMOTE" "$HOST"; do
  [[ -f "$file" ]] || fail "missing $(basename "$file")"
done

python3 - "$ENROLLMENT" "$VIEW_MODEL" <<'PY'
import pathlib
import sys

enrollment = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
view_model = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

def method_body(name: str, next_name: str) -> str:
    return enrollment.split(f"private async Task {name}", 1)[1].split(
        f"private async Task {next_name}", 1
    )[0]

for body in (
    method_body("AddParticipantAsync()", "AddNetworkAsync()"),
    method_body("ManualAddNetworkAsync()", "CreateNetworkAsync()"),
):
    if body.count("BeginJoinCoordinationRefresh();") != 1:
        raise SystemExit("join action does not arm exactly one refresh window")
    if body.index("DispatchAsync(") > body.index("BeginJoinCoordinationRefresh();"):
        raise SystemExit("join refresh window starts before dispatch completes")
    if "EndJoinCoordinationRefresh();" in body:
        raise SystemExit("failed join action still needs a pre-dispatch refresh rollback")

for contract in (
    "private readonly NativeCoreCallGate _nativeCoreCallGate = new();",
    "_nativeCoreCallGate.TryEnterRefresh()",
    "await _nativeCoreCallGate.EnterDispatchAsync()",
):
    if contract not in view_model:
        raise SystemExit(f"Windows native calls do not share one gate: {contract}")
PY

for identifier in \
  ManualJoinCreateNetworkChoice \
  ManualJoinCreateNetworkName \
  ManualJoinCreateNetworkSubmit \
  ManualJoinJoinerDeviceIdValue \
  ManualJoinAdminDeviceIdValue \
  ManualJoinAdminNetworkIdValue
do
  grep -Fq "$identifier" "$XAML" \
    || fail "shipped Windows UI lacks $identifier"
done
for mode in Reset Bootstrap CreateAdmin AdminAdd ManualJoin Verify; do
  grep -Fq "\"$mode\"" "$DRIVER" \
    || fail "Windows UI driver lacks $mode"
done
grep -Fq '"ReadDaemonLog"' "$REMOTE" \
  || fail "Windows remote wrapper cannot preserve daemon failure evidence"
for bootstrap_contract in \
  'Read-PublicText "ManualJoinJoinerDeviceIdValue"' \
  '$Evidence.joinerNpub = $Joiner'
do
  grep -Fq "$bootstrap_contract" "$DRIVER" \
    || fail "Windows Bootstrap does not preflight its joiner identity"
done
for roster_contract in \
  'Wait-SinglePeerConnectedRoster' \
  'Test-VisibleControlName $Window "1 of 1 connected"' \
  'Test-VisibleControlName $Window "Online"' \
  'single-peer connected roster row'
do
  grep -Fq "$roster_contract" "$DRIVER" \
    || fail "Windows driver lacks public roster status: $roster_contract"
done
[[ "$(grep -Fc '"RosterParticipantAccepted-$ParticipantNpub"' "$DRIVER")" -eq 2 ]] \
  || fail "Windows admin and relaunch checks do not observe the exact public roster row"
grep -Fq '$Evidence.relaunchAccepted = $true' "$DRIVER" \
  || fail "Windows driver lacks relaunch acceptance evidence"
grep -Fq 'publicUiOnly = $true' "$DRIVER" \
  || fail "Windows action evidence is not public-UI-only"
grep -Fq 'privateStateRead = $false' "$DRIVER" \
  || fail "Windows action evidence does not reject private readback"
for canonical_readback_contract in \
  'function ConvertTo-CanonicalIpCsv' \
  "(\$Value -split '[,\\s]+')" \
  '[System.Net.IPAddress]::TryParse' \
  'Sort-Object -Unique' \
  'ConvertTo-CanonicalIpCsv (' \
  'Read-ControlValue "ExitDnsBootstrapIps"' \
  'ConvertTo-CanonicalIpCsv $DnsBootstrapIps'
do
  grep -Fq "$canonical_readback_contract" "$DRIVER" \
    || fail "Windows custom DoH relaunch readback is not canonical IP-set evidence"
done

grep -Fq 'windows-release-artifact.json' "$REMOTE" \
  || fail "Windows remote wrapper has no artifact receipt"
grep -Fq 'NostrVpn.Windows.exe' "$HOST" \
  || fail "Windows host wrapper does not select the Release app"
for artifact in nostr_vpn_app_core.dll nvpn.exe; do
  grep -Fq "$artifact" "$REMOTE" \
    || fail "Windows artifact receipt does not bind $artifact"
done
for service_contract in \
  '$ServiceName = "NvpnService"' \
  'Get-Service -Name $ServiceName' \
  'Stop-Service -Name $ServiceName' \
  'Get-CimInstance Win32_Service' \
  'Get-Sha256 $ServiceExecutable' \
  'Get-Sha256 $CliExe' \
  'Normalize-ComparableWindowsPath' \
  "\$ConfigArgument.Groups['config'].Value" \
  "^ daemon --service --config \"(?<config>[^\"]+)\" --iface \"(?<iface>[^\"]+)\" --mesh-refresh-interval-secs (?<refresh>[1-9][0-9]*)\\s*\$" \
  '$CliExe service uninstall --config $Config' \
  'WINDOWS_RELEASE_MOBILE_JOIN_CLEAN'
do
  grep -Fq "$service_contract" "$REMOTE" \
    || fail "Windows wrapper does not use the production service name"
done
if grep -Fq "^ daemon --service --config \"(?<config>[^\"]+)\"\\s*\$" "$REMOTE"; then
  fail "Windows cleanup ownership matcher still rejects canonical service arguments"
fi
if grep -Fq '"(?: |$)' "$REMOTE"; then
  fail "Windows cleanup ownership matcher still permits trailing arguments"
fi
if grep -Fq ".StartsWith(" "$REMOTE" \
  && grep -Fq '$ExpectedArguments' "$REMOTE"
then
  fail "Windows cleanup still compares raw service arguments"
fi
grep -Fq 'windows-cleanup.log' "$HOST" \
  || fail "Windows cleanup evidence is discarded"
grep -Fq 'remote ReadDaemonLog >"$PLATFORM_RESULT/windows-daemon-failure.log"' "$HOST" \
  || fail "Windows failure cleanup discards the daemon delivery log"
daemon_capture_line="$(grep -n 'remote ReadDaemonLog >' "$HOST" | head -n 1 | cut -d: -f1)"
remote_cleanup_line="$(grep -n 'remote Cleanup >' "$HOST" | head -n 1 | cut -d: -f1)"
[[ -n "$daemon_capture_line" && -n "$remote_cleanup_line" \
  && "$daemon_capture_line" -lt "$remote_cleanup_line" ]] \
  || fail "Windows daemon evidence is captured after destructive cleanup"
if grep -Fq 'remote Cleanup >/dev/null 2>&1 || true' "$HOST"; then
  fail "Windows cleanup failure is still ignored"
fi
if grep -Eq '(Get|Stop)-Service -Name "nvpn"' "$REMOTE"; then
  fail "Windows wrapper still queries the obsolete service name"
fi
if grep -Eq 'cargo (build|run)|dotnet (build|publish)|windows-build\\.ps1' "$REMOTE" "$HOST"; then
  fail "physical Windows/Pixel phase compiles instead of reusing Release artifacts"
fi
grep -Fq -- '-NoProfile -NonInteractive -ExecutionPolicy Bypass' "$HOST" \
  || fail "Windows/Pixel runner lacks bounded script execution-policy bypass"
for stderr_log in \
  'remote Prepare 2>&1 | tee' \
  'remote Verify >"$PLATFORM_RESULT/$label-relaunch.log" 2>&1' \
  'remote Reset >"$PLATFORM_RESULT/desktop-admin-reset.log" 2>&1'
do
  grep -Fq -- "$stderr_log" "$HOST" \
    || fail "Windows/Pixel runner does not retain stderr: $stderr_log"
done

for evidence in \
  release_join_android_wait_accepted_participant \
  verify_desktop_relaunch \
  verify_pixel_relaunch \
  desktop_mobile_manual_join_receipt.py \
  'RELEASE_JOIN_DELIVERY_WAIT_SECS <= 15'
do
  grep -Fq "$evidence" "$HOST" \
    || fail "Windows/Pixel orchestrator lacks $evidence"
done
artifact_validated_line="$(grep -n 'RELEASE_JOIN_ARTIFACTS_VALIDATED=1' "$HOST" | head -n 1 | cut -d: -f1)"
first_android_reset_line="$(grep -n 'release_join_reset_android_state' "$HOST" | head -n 1 | cut -d: -f1)"
[[ -n "$artifact_validated_line" && -n "$first_android_reset_line" \
  && "$artifact_validated_line" -lt "$first_android_reset_line" ]] \
  || fail "Windows mutates the Pixel before validating the reused signed artifact"
desktop_admin_phase="$(
  sed -n \
    '/# Windows admin -> Pixel joiner\./,/# Pixel admin -> Windows joiner\./p' \
    "$HOST"
)"
for timing_contract in \
  WINDOWS_ADMIN_DEADLINE_HOST_MS \
  release_join_observe_pair_until_ms \
  windows_admin_desktop_visible \
  windows_admin_pixel_visible \
  WINDOWS_DESKTOP_ACCEPTED_HOST_MS \
  WINDOWS_PIXEL_ACCEPTED_HOST_MS
do
  grep -Fq "$timing_contract" <<<"$desktop_admin_phase" \
    || fail "Windows desktop-admin timing lacks $timing_contract"
done
[[ "$(grep -Fc 'release_join_observe_pair_until_ms' <<<"$desktop_admin_phase")" -eq 1 ]] \
  || fail "Windows desktop and Pixel acceptance do not share one observer deadline"
timing_line="$(
  grep -n 'WINDOWS_ADMIN_DELIVERY_MS=' <<<"$desktop_admin_phase" \
    | tail -n 1 | cut -d: -f1
)"
durability_line="$(grep -n 'verify_desktop_relaunch' <<<"$desktop_admin_phase" | cut -d: -f1)"
[[ -n "$timing_line" && -n "$durability_line" && "$timing_line" -lt "$durability_line" ]] \
  || fail "Windows durability runs before concurrent acceptance timing closes"
for reverse_contract in \
  'release_join_android_manual_admin_prepare "$WINDOWS_JOINER_ID"' \
  'remote ManualJoin' \
  'release_join_android_manual_admin_tap "$WINDOWS_JOINER_ID"' \
  'WINDOWS_REVERSE_DEADLINE_HOST_MS' \
  'release_join_observe_pair_until_ms'
do
  grep -Fq "$reverse_contract" "$HOST" \
    || fail "Windows reverse join lacks two-phase coordination: $reverse_contract"
done
for component_binding in \
  --android-artifact-receipt \
  --android-fips-metadata-receipt \
  --expected-desktop-app-sha \
  --expected-android-app-sha \
  --expected-desktop-fips-sha \
  --expected-android-fips-sha
do
  grep -Fq -- "$component_binding" "$HOST" \
    || fail "Windows/Pixel receipt lacks $component_binding"
done
if grep -Fq 'desktop_manual_join_e2e_fixture' "$DRIVER" "$REMOTE" "$HOST"; then
  fail "Windows/Pixel acceptance invokes the private manual-join fixture"
fi

echo "WINDOWS_RELEASE_MOBILE_JOIN_HARNESS_OK"
