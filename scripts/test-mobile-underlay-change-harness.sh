#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
continuity="$ROOT/scripts/validate-mobile-underlay-continuity.py"
ios_output_capture="$ROOT/scripts/capture-mobile-ios-underlay-output.py"
android_lib="$ROOT/scripts/lib-mobile-android-underlay.sh"
android_release_lib="$ROOT/scripts/lib-mobile-android-release-gate.sh"
android_service="$ROOT/android/app/src/main/java/org/nostrvpn/app/vpn/NostrVpnService.kt"
ios_test="$ROOT/ios/UITests/NostrVpnReleaseNetworkUITests.swift"
ios_underlay="$ROOT/ios/UITests/NostrVpnReleaseNetworkUnderlay.swift"
network_evidence="$ROOT/scripts/release-network-evidence.py"
mobile_exit_gate="$ROOT/scripts/mobile-wireguard-exit-e2e.sh"
release_gate="$ROOT/scripts/release-gate.sh"
temp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-mobile-underlay-harness.XXXXXX")"
trap 'rm -rf "$temp"' EXIT

# The continuity command can exit while a detached descendant still holds its
# stdout pipe open. Stopping the observer must not wait for that pipe to close.
python3 - "$ROOT/scripts/mobile-underlay-local-timestamp.py" "$temp" <<'PY'
import os
import pathlib
import signal
import subprocess
import sys
import time

observer_script = pathlib.Path(sys.argv[1])
temp = pathlib.Path(sys.argv[2])
holder_pid_path = temp / "continuity-pipe-holder.pid"
output_path = temp / "continuity-observer.log"
fixture = """
import pathlib
import subprocess
import sys

holder = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"],
    start_new_session=True,
    stdout=sys.stdout,
    stderr=sys.stderr,
)
pathlib.Path(sys.argv[1]).write_text(str(holder.pid), encoding="utf-8")
print("fixture ready", flush=True)
"""
observer = subprocess.Popen(
    [
        sys.executable,
        str(observer_script),
        str(output_path),
        "--",
        sys.executable,
        "-c",
        fixture,
        str(holder_pid_path),
    ]
)
holder_pid = None
try:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if holder_pid_path.exists():
            holder_pid = int(holder_pid_path.read_text(encoding="utf-8"))
            break
        if observer.poll() is not None:
            raise SystemExit("continuity observer exited before fixture was ready")
        time.sleep(0.01)
    if holder_pid is None:
        raise SystemExit("continuity pipe-holder fixture did not start")
    time.sleep(0.1)
    if observer.poll() is not None:
        raise SystemExit("continuity observer did not remain blocked on the inherited pipe")
    observer.terminate()
    try:
        status = observer.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise SystemExit("continuity observer did not stop while its pipe stayed open") from error
    if status != 0:
        raise SystemExit(f"continuity observer stopped with status {status}")
finally:
    if observer.poll() is None:
        observer.kill()
        observer.wait()
    if holder_pid is not None:
        try:
            os.killpg(holder_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
PY

write_ping_fixture() {
  cat >"$temp/ping.log" <<'EOF'
[1000.000] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=1 ms
[1000.200] 64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=1 ms
[1001.200] 64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=1 ms
[1006.200] 64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=1 ms
[1006.400] 64 bytes from 10.0.0.2: icmp_seq=5 ttl=64 time=1 ms
[1006.600] 64 bytes from 10.0.0.2: icmp_seq=6 ttl=64 time=1 ms
[1006.800] 64 bytes from 10.0.0.2: icmp_seq=7 ttl=64 time=1 ms
EOF
}

cat >"$temp/markers.tsv" <<'EOF'
switch_1_requested	1000500
switch_1_outage	1000700
switch_1_recovery_requested	1001000
switch_1_underlay_validated	1006000
switch_1_payload_recovery	200
switch_1_verified	1006900
EOF
write_ping_fixture
python3 "$continuity" \
  "$temp/ping.log" "$temp/markers.tsv" "$temp/continuity.json" \
  Android 4000 \
  >/dev/null
python3 - "$temp/continuity.json" <<'PY'
import json
import sys

receipt = json.load(open(sys.argv[1], encoding="utf-8"))
assert receipt["passed"] is True
cycle = receipt["cycles"][0]
assert cycle["outageReversePayloads"] == 0
assert cycle["firstReversePayloadRecoveryMilliseconds"] == 0
assert cycle["dnsAndWireGuardRecoveryMilliseconds"] == 200
assert cycle["dnsRecoveryMilliseconds"] == 200
assert cycle["underlayAssociationMilliseconds"] == 5000
assert cycle["reversePayloadRecoveredBeforeValidation"] is True
for fabricated in (
    "appProcessContinuity",
    "outageObserved",
    "noCellularFallback",
    "originalValidatedWifiRestored",
    "dnsAndWireGuardPayloadRecovery",
    "tunnelProcessContinuity",
):
    assert fabricated not in cycle
assert receipt["bidirectionalPayload"].startswith("wireguard-server-icmp")
PY

# ICMP replies can legitimately arrive out of sequence after an underlay
# outage. Arrival timestamps and unique payloads, not sequence ordering, prove
# that this is live continuity evidence.
sed \
  -e 's/icmp_seq=6 ttl/icmp_seq=TEMP ttl/' \
  -e 's/icmp_seq=7 ttl/icmp_seq=6 ttl/' \
  -e 's/icmp_seq=TEMP ttl/icmp_seq=7 ttl/' \
  "$temp/ping.log" >"$temp/reordered-replies.log"
python3 "$continuity" \
  "$temp/reordered-replies.log" "$temp/markers.tsv" \
  "$temp/reordered-replies.json" Android 4000 \
  >/dev/null
jq -e '.passed == true and .successfulPayloads == 7' \
  "$temp/reordered-replies.json" >/dev/null

cp "$temp/ping.log" "$temp/duplicate-reply.log"
printf '%s\n' \
  '[1006.850] 64 bytes from 10.0.0.2: icmp_seq=7 ttl=64 time=1 ms (DUP!)' \
  >>"$temp/duplicate-reply.log"
python3 "$continuity" \
  "$temp/duplicate-reply.log" "$temp/markers.tsv" \
  "$temp/duplicate-reply.json" Android 4000 \
  >/dev/null
jq -e \
  '.passed == true and .successfulPayloads == 7 and .duplicatePayloads == 1' \
  "$temp/duplicate-reply.json" >/dev/null

head -n 5 "$temp/ping.log" >"$temp/too-few-unique-replies.log"
if python3 "$continuity" \
  "$temp/too-few-unique-replies.log" "$temp/markers.tsv" \
  "$temp/too-few-unique-replies.json" Android 4000 \
  >"$temp/too-few-unique-replies.out" \
  2>"$temp/too-few-unique-replies.err"
then
  echo "continuity validator accepted fewer than six unique replies" >&2
  exit 1
fi
grep -Fq "only 5 unique bidirectional payloads" \
  "$temp/too-few-unique-replies.err"

cp "$temp/markers.tsv" "$temp/slow-product-markers.tsv"
python3 - "$temp/slow-product-markers.tsv" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(
    path.read_text(encoding="utf-8").replace(
        "switch_1_payload_recovery\t200\n",
        "switch_1_payload_recovery\t4100\n",
    ),
    encoding="utf-8",
)
PY
write_ping_fixture
if python3 "$continuity" \
  "$temp/ping.log" "$temp/slow-product-markers.tsv" \
  "$temp/slow-product.json" Android 4000 \
  >"$temp/slow-product.out" 2>"$temp/slow-product.err"
then
  echo "continuity validator accepted slow product recovery" >&2
  exit 1
fi
grep -Fq "DNS recovery was 4100ms" "$temp/slow-product.err"

cat >"$temp/later-wireguard.log" <<'EOF'
[1000.000] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=1 ms
[1000.200] 64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=1 ms
[1000.400] 64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=1 ms
[1006.700] 64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=1 ms
[1006.900] 64 bytes from 10.0.0.2: icmp_seq=5 ttl=64 time=1 ms
[1007.100] 64 bytes from 10.0.0.2: icmp_seq=6 ttl=64 time=1 ms
EOF
python3 "$continuity" \
  "$temp/later-wireguard.log" "$temp/markers.tsv" \
  "$temp/later-wireguard.json" Android 4000 \
  >/dev/null
jq -e '
  .cycles[0].dnsRecoveryMilliseconds == 200
  and .cycles[0].firstReversePayloadRecoveryMilliseconds == 700
  and .cycles[0].dnsAndWireGuardRecoveryMilliseconds == 700
  and .cycles[0].recoveryMilliseconds == 700
' "$temp/later-wireguard.json" >/dev/null

grep -Ev 'switch_1_underlay_validated' \
  "$temp/markers.tsv" >"$temp/ambiguous-old-markers.tsv"
if python3 "$continuity" \
  "$temp/ping.log" "$temp/ambiguous-old-markers.tsv" \
  "$temp/ambiguous-old.json" Android 4000 \
  >"$temp/ambiguous-old.out" 2>"$temp/ambiguous-old.err"
then
  echo "continuity validator accepted an ambiguous legacy receipt" >&2
  exit 1
fi
grep -Fq "missing marker switch_1_underlay_validated" \
  "$temp/ambiguous-old.err"

cp "$temp/markers.tsv" "$temp/no-outage.tsv"
sed -i '' '/switch_1_outage/d' "$temp/no-outage.tsv"
if python3 "$continuity" \
  "$temp/ping.log" "$temp/no-outage.tsv" "$temp/no-outage.json" \
  Android 4000 \
  >"$temp/no-outage.out" 2>"$temp/no-outage.err"
then
  echo "continuity validator accepted a radio bounce without observed outage" >&2
  exit 1
fi
grep -Fq "missing marker switch_1_outage" "$temp/no-outage.err"

sed 's/switch_1_outage	1000700/switch_1_outage	1001000/' \
  "$temp/markers.tsv" >"$temp/zero-outage-window.tsv"
if python3 "$continuity" \
  "$temp/ping.log" "$temp/zero-outage-window.tsv" \
  "$temp/zero-outage-window.json" Android 4000 \
  >"$temp/zero-outage-window.out" 2>"$temp/zero-outage-window.err"
then
  echo "continuity validator accepted a zero-duration outage window" >&2
  exit 1
fi
grep -Fq "request <= outage < radio-on-requested" \
  "$temp/zero-outage-window.err"

cp "$temp/ping.log" "$temp/outage-reply.log"
printf '%s\n' \
  '[1000.800] 64 bytes from 10.0.0.2: icmp_seq=99 ttl=64 time=1 ms' \
  >>"$temp/outage-reply.log"
if python3 "$continuity" \
  "$temp/outage-reply.log" "$temp/markers.tsv" \
  "$temp/outage-reply.json" Android 4000 \
  >"$temp/outage-reply.out" 2>"$temp/outage-reply.err"
then
  echo "continuity validator accepted reverse payload during the outage" >&2
  exit 1
fi
grep -Fq "reverse payloads between outage and radio-on request" \
  "$temp/outage-reply.err"

python3 - \
  "$network_evidence" "$temp/continuity.json" \
  "$temp/outage-reply.log" "$temp/markers.tsv" \
  "$temp/ping.log" "$temp/zero-outage-window.tsv" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("network_evidence", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
summary = pathlib.Path(sys.argv[2])
for ping, markers in ((sys.argv[3], sys.argv[4]), (sys.argv[5], sys.argv[6])):
    try:
        module.validate_underlay_continuity(
            summary, "Android", pathlib.Path(ping), pathlib.Path(markers)
        )
    except ValueError:
        pass
    else:
        raise SystemExit("evidence builder accepted raw data that contradicts summary")
PY

cat >"$temp/late-reverse.log" <<'EOF'
[1000.000] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=1 ms
[1000.200] 64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=1 ms
[1010.200] 64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=1 ms
[1010.400] 64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=1 ms
[1010.600] 64 bytes from 10.0.0.2: icmp_seq=5 ttl=64 time=1 ms
[1010.800] 64 bytes from 10.0.0.2: icmp_seq=6 ttl=64 time=1 ms
EOF
sed 's/switch_1_verified	1006900/switch_1_verified	1010900/' \
  "$temp/markers.tsv" >"$temp/late-reverse-markers.tsv"
if python3 "$continuity" \
  "$temp/late-reverse.log" "$temp/late-reverse-markers.tsv" \
  "$temp/late-reverse.json" iOS 4000 \
  >"$temp/late-reverse.out" 2>"$temp/late-reverse.err"
then
  echo "continuity validator accepted a late first reverse payload" >&2
  exit 1
fi
grep -Fq "first reverse payload after validation was 4200ms" \
  "$temp/late-reverse.err"

printf '%s\n' \
  'NVPN_IOS_UNDERLAY_SWITCH_1_REQUESTED_MS=1' \
  'ordinary xcodebuild output' \
  'NVPN_IOS_UNDERLAY_SWITCH_1_OUTAGE_MS=2' \
  'NVPN_IOS_UNDERLAY_SWITCH_1_RECOVERY_REQUESTED_MS=3' \
  'NVPN_IOS_UNDERLAY_SWITCH_1_UNDERLAY_VALIDATED_MS=4' \
  'NVPN_IOS_UNDERLAY_SWITCH_1_PAYLOAD_RECOVERY_MS=200' \
  'NVPN_IOS_UNDERLAY_SWITCH_1_VERIFIED_MS=5' \
  | python3 "$ios_output_capture" \
    "$temp/xcode.log" "$temp/ios-host-markers.tsv"
grep -Fxq 'ordinary xcodebuild output' "$temp/xcode.log"
python3 - "$temp/ios-host-markers.tsv" <<'PY'
import sys

rows = [
    line.rstrip().split("\t")
    for line in open(sys.argv[1], encoding="utf-8")
]
assert [row[0] for row in rows] == [
    "switch_1_requested",
    "switch_1_outage",
    "switch_1_recovery_requested",
    "switch_1_underlay_validated",
    "switch_1_payload_recovery",
    "switch_1_verified",
]
assert all(value.isdigit() for _, value in rows)
values = dict(rows)
assert values["switch_1_payload_recovery"] == "200"
timeline = [
    row for row in rows
    if not row[0].endswith("_payload_recovery")
]
assert all(
    int(current[1]) >= int(previous[1])
    for previous, current in zip(timeline, timeline[1:])
)
PY

if printf '%s\n' \
  'NVPN_IOS_UNDERLAY_SWITCH_1_REQUESTED_MS=1' \
  'NVPN_IOS_UNDERLAY_SWITCH_1_REQUESTED_MS=2' \
  | python3 "$ios_output_capture" \
    "$temp/duplicate-xcode.log" "$temp/duplicate-ios-host-markers.tsv" \
    >"$temp/duplicate.out" 2>"$temp/duplicate.err"
then
  echo "iOS underlay capture accepted a duplicate timeline marker" >&2
  exit 1
fi
grep -Fq 'duplicate iOS underlay markers: switch_1_requested' \
  "$temp/duplicate.err"

python3 - "$ios_output_capture" "$temp" <<'PY'
import importlib.util
import io
import json
import pathlib
import sys
from contextlib import redirect_stderr

spec = importlib.util.spec_from_file_location("ios_capture", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class FinishedThread:
    def join(self, timeout=None):
        pass

    def is_alive(self):
        return False

def finish(samples, name):
    path = pathlib.Path(sys.argv[2], name)
    sampler = module.ProcessSampler("fixture-device", path)
    sampler.thread = FinishedThread()
    sampler.begin_seen = True
    sampler.end_seen = True
    sampler.samples = samples
    sampler.required_checkpoints = {row["checkpoint"] for row in samples}
    sampler.direct_acknowledgements = (
        sampler.required_checkpoints & module.DIRECT_CHECKPOINTS
    )
    status = sampler.finish()
    return status, json.loads(path.read_text(encoding="utf-8"))

sampler = module.ProcessSampler(
    "fixture-device", pathlib.Path(sys.argv[2], "unused.json")
)
module.DIRECT_SAMPLE_RETRY_SECONDS = 0
module.DIRECT_SAMPLE_TIMEOUT_SECONDS = 0.001
calls = []
sampler._sample = (
    lambda checkpoint, timeout=5: calls.append(checkpoint) or len(calls) == 2
)
assert sampler._sample_checkpoint("release_connected_direct_passed") is True
assert calls == ["release_connected_direct_passed"] * 2
calls.clear()
sampler._sample = lambda checkpoint, timeout=5: calls.append(checkpoint) or False
assert sampler._sample_checkpoint("release_connected_direct_passed") is False
assert len(calls) > 1 and set(calls) == {"release_connected_direct_passed"}
calls.clear()
assert sampler._sample_checkpoint("active-session-begin") is False
assert calls == ["active-session-begin"]

calls.clear()
acks = []
sampler._sample = (
    lambda checkpoint, timeout=5: calls.append(checkpoint) or len(calls) == 2
)
sampler._write_runner_acknowledgement = (
    lambda checkpoint, run_id: acks.append((checkpoint, run_id)) or None
)
assert sampler._observe_direct_checkpoint(
    "release_connected_direct_passed", "fixture-run"
) is True
assert calls == ["release_connected_direct_passed"] * 2
assert acks == [("release_connected_direct_passed", "fixture-run")]
assert sampler.direct_acknowledgements == {"release_connected_direct_passed"}
sampler.checkpoint_executor.shutdown(wait=False, cancel_futures=True)

mapped = []
sampler = module.ProcessSampler(
    "fixture-device", pathlib.Path(sys.argv[2], "mapped.json")
)
sampler._observe_direct_checkpoint = (
    lambda checkpoint, run_id: mapped.append((checkpoint, run_id)) or True
)
sampler.observe_direct_checkpoint(
    "RELEASE_CONNECTED_DIRECT_RELAUNCH_READY", "fixture-run"
)
for future in sampler.checkpoint_futures:
    assert future.result(timeout=1) is True
assert mapped == [("release_connected_direct_relaunch_passed", "fixture-run")]
assert sampler.required_checkpoints == {
    "release_connected_direct_relaunch_passed"
}
sampler.checkpoint_executor.shutdown(wait=False, cancel_futures=True)

copied = []
original_run = module.subprocess.run
def record_copy(command, **kwargs):
    source = pathlib.Path(command[command.index("--upload") + 1])
    copied.append((command, source.read_text(encoding="utf-8")))
    return type("Completed", (), {"returncode": 0})()
module.subprocess.run = record_copy
sampler = module.ProcessSampler(
    "fixture-device",
    pathlib.Path(sys.argv[2], "copy.json"),
    "fixture.runner",
)
assert sampler._write_runner_acknowledgement(
    "release_connected_direct_passed", "fixture-run"
) is None
command, contents = copied[0]
assert command[:4] == ["ios-deploy", "--id", "fixture-device", "--no-wifi"]
assert command[command.index("--to") + 1] == (
    "Documents/nvpn-host-process-ack.log"
)
assert command[command.index("--bundle_id") + 1] == "fixture.runner"
assert contents == (
    "NVPN_XCUITEST_RUN_ID=fixture-run\n"
    "NVPN_IOS_HOST_PROCESS_OBSERVED=release_connected_direct_passed\n"
)
module.subprocess.run = original_run
sampler.checkpoint_executor.shutdown(wait=False, cancel_futures=True)
samples = [
    {"checkpoint": "active-session-begin", "appPids": [111], "packetTunnelPids": [211]},
    {"checkpoint": "underlay_switch_1_outage", "appPids": [111], "packetTunnelPids": [211]},
    {"checkpoint": "active-session-end", "appPids": [111], "packetTunnelPids": [211]},
    {"checkpoint": "release_connected_direct_passed", "appPids": [112], "packetTunnelPids": [211]},
]
status, receipt = finish(samples, "active-processes.json")
assert status == 0 and receipt["passed"] is True
assert receipt["appProcessIdentifiers"] == [111]
assert receipt["packetTunnelProcessIdentifiers"] == [211]
assert receipt["directCheckpointProcesses"] == {
    "release_connected_direct_passed": {
        "appProcessIdentifier": 112,
        "packetTunnelProcessIdentifier": 211,
    }
}
assert receipt["directRunnerAcknowledgements"] == [
    "release_connected_direct_passed",
]

samples[1] = {**samples[1], "packetTunnelPids": []}
status, receipt = finish(samples, "disconnected-active-processes.json")
assert status == 1 and receipt["passed"] is False
assert "underlay_switch_1_outage" not in receipt["observedCheckpoints"]

assert module.ACTIVE_TUNNEL_CHECKPOINT.search(
    "NVPN_IOS_RELEASE_CONNECTED_DIRECT_PASSED=1"
) is None
assert module.DIRECT_READY.search(
    "NVPN_IOS_RELEASE_CONNECTED_DIRECT_RELAUNCH_READY=1"
) is not None

missing_end = module.ProcessSampler(
    "fixture-device", pathlib.Path(sys.argv[2], "missing-end.json")
)
missing_end.thread = FinishedThread()
missing_end.begin_seen = True
missing_end.samples = [
    {"checkpoint": "active-session-begin", "appPids": [111], "packetTunnelPids": [211]}
]
missing_end.required_checkpoints = {"active-session-begin"}
diagnostics = io.StringIO()
with redirect_stderr(diagnostics):
    assert missing_end.finish(report_errors=False) == 1
assert diagnostics.getvalue() == "", repr(diagnostics.getvalue())

missing_ack_samples = [dict(row) for row in samples]
missing_ack_samples[1]["packetTunnelPids"] = [211]
path = pathlib.Path(sys.argv[2], "missing-direct-ack.json")
missing_ack = module.ProcessSampler("fixture-device", path)
missing_ack.thread = FinishedThread()
missing_ack.begin_seen = True
missing_ack.end_seen = True
missing_ack.samples = missing_ack_samples
missing_ack.required_checkpoints = {
    row["checkpoint"] for row in missing_ack_samples
}
assert missing_ack.finish() == 1
receipt = json.loads(path.read_text(encoding="utf-8"))
assert receipt["passed"] is False
assert any("without runner acknowledgement" in error for error in receipt["errors"])
PY

cat >"$temp/adb" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == *" logcat "* ]]; then
  printf '%s\n' \
    'I/NostrVpnService: WG upstream socket fd from native runtime: 41 (-1 means WG upstream not running)' \
    'I/NostrVpnService: WG upstream socket fd from native runtime: 42 (-1 means WG upstream not running)' \
    'I/NostrVpnService: Physical network changed; live FIPS carriers refreshed'
else
  printf '%s\n' "Wifi is disabled"
fi
SH
chmod +x "$temp/adb"
bash -eu -c '
  source "$1"
  ADB="$2"
  serial="physical-device"
  android_underlay_wait_wifi_radio disabled 1
' _ "$android_lib" "$temp/adb"
bash -eu -o pipefail -c '
  source "$1"
  ADB="$2"
  serial="physical-device"
  [[ "$(android_vpn_native_start_count)" == 2 ]]
' _ "$android_lib" "$temp/adb"

cat >"$temp/adb-connectivity" <<'SH'
#!/usr/bin/env bash
case "${ADB_CONNECTIVITY_MODE:-none}" in
  fallback)
    cat <<'EOF'
Active default network: 102
Current Networks:
NetworkAgentInfo{ network{101} ni{WIFI CONNECTED} NOT_VPN VALIDATED LinkProperties{Routes: [0.0.0.0/0 -> 192.0.2.1]}}
NetworkAgentInfo{ network{102} ni{VPN CONNECTED} VALIDATED}
Status for known UIDs:
EOF
    ;;
  none)
    cat <<'EOF'
Active default network: 102
Current Networks:
NetworkAgentInfo{ network{102} ni{VPN CONNECTED} VALIDATED LinkProperties{Routes: [0.0.0.0/0 -> 10.0.0.1]}}
Status for known UIDs:
EOF
    ;;
  malformed)
    printf 'connectivity service returned no parseable network records\n'
    ;;
  truncated)
    printf '%s\n' \
      'Active default network: 102' \
      'Current Networks:' \
      'NetworkAgentInfo{ network{102} ni{VPN CONNECTED} VALIDATED' \
      'Status for known UIDs:'
    ;;
  failure)
    exit 17
    ;;
esac
SH
chmod +x "$temp/adb-connectivity"
bash -eu -o pipefail -c '
  source "$1"
  ADB="$2"
  serial="physical-device"
  ADB_CONNECTIVITY_MODE=fallback
  export ADB_CONNECTIVITY_MODE
  android_underlay_has_validated_physical_fallback
  ADB_CONNECTIVITY_MODE=none
  export ADB_CONNECTIVITY_MODE
  status=0
  android_underlay_has_validated_physical_fallback || status=$?
  [[ "$status" -eq 1 ]]
  for mode in malformed truncated failure; do
    ADB_CONNECTIVITY_MODE="$mode"
    export ADB_CONNECTIVITY_MODE
    status=0
    android_underlay_has_validated_physical_fallback || status=$?
    [[ "$status" -eq 2 ]]
  done
  android_underlay_has_validated_physical_fallback() { return 2; }
  if android_underlay_wait_offline /dev/null; then
    echo "Android offline gate accepted an inspection error" >&2
    exit 1
  fi
' _ "$android_lib" "$temp/adb-connectivity"

cat >"$temp/adb-logcat" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${3:-}" == "logcat" ]]; then
  cat "$ANDROID_LOGCAT_FIXTURE"
  exit 0
fi
exit 2
SH
chmod +x "$temp/adb-logcat"
cat >"$temp/native-start-window-full.log" <<'EOF'
I/NostrVpnService( 100): WG upstream socket fd from native runtime: 41
I/NostrVpnService( 100): NVPN_RELEASE_LOG_WINDOW_test-marker
I/NostrVpnService( 100): WG upstream socket fd from native runtime: 42
EOF
cat >"$temp/native-start-window-truncated.log" <<'EOF'
I/NostrVpnService( 100): NVPN_RELEASE_LOG_WINDOW_test-marker
I/NostrVpnService( 100): WG upstream socket fd from native runtime: 42
EOF
cat >"$temp/native-start-window-marker-lost.log" <<'EOF'
I/NostrVpnService( 100): WG upstream socket fd from native runtime: 42
EOF
bash -eu -o pipefail -c '
  source "$1"
  ADB="$2"
  serial="physical-device"
  ANDROID_VPN_LOG_MARKER="NVPN_RELEASE_LOG_WINDOW_test-marker"
  ANDROID_LOGCAT_FIXTURE="$3"
  export ANDROID_LOGCAT_FIXTURE
  [[ "$(android_vpn_native_start_count)" == 1 ]]
  ANDROID_LOGCAT_FIXTURE="$4"
  export ANDROID_LOGCAT_FIXTURE
  [[ "$(android_vpn_native_start_count)" == 1 ]]
  ANDROID_LOGCAT_FIXTURE="$5"
  export ANDROID_LOGCAT_FIXTURE
  if android_vpn_native_start_count >"$6" 2>"$7"; then
    echo "Android native-start count accepted a lost log marker" >&2
    exit 1
  fi
  grep -Fq "native-start log marker is no longer present" "$7"
' _ "$android_lib" "$temp/adb-logcat" \
  "$temp/native-start-window-full.log" \
  "$temp/native-start-window-truncated.log" \
  "$temp/native-start-window-marker-lost.log" \
  "$temp/native-start-window-marker-lost.out" \
  "$temp/native-start-window-marker-lost.err"

bash -eu -o pipefail -c '
  source "$1"
  source "$2"
  native_starts=3
  log_window_resets=0
  android_vpn_begin_log_window() {
    log_window_resets=$((log_window_resets + 1))
    native_starts=0
  }
  android_vpn_native_start_count() { printf "%s\n" "$native_starts"; }
  android_release_capture_native_tunnel_start_baseline
  [[ "$log_window_resets" == 1 ]]
  [[ "$ANDROID_RELEASE_NATIVE_TUNNEL_START_BASELINE" == 0 ]]
  native_starts=1
  android_release_pin_native_tunnel_start_count
  [[ "$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT" == 1 ]]
  android_release_assert_native_tunnel_unchanged stable-network-phase
  native_starts=2
  if android_release_assert_native_tunnel_unchanged recreated-network-phase; then
    echo "Android Release gate accepted native-tunnel recreation" >&2
    exit 1
  fi
  native_starts=9
  android_release_capture_native_tunnel_start_baseline
  [[ "$log_window_resets" == 2 ]]
  native_starts=2
  if android_release_pin_native_tunnel_start_count; then
    echo "Android Release gate accepted duplicate starts from one UI connect" >&2
    exit 1
  fi
' _ "$android_lib" "$android_release_lib"

cat >"$temp/android-marker-proof.tsv" <<'EOF'
proof_app_radio-bounce-start	123
proof_app_radio-off	123
proof_app_radio-on	123
proof_app_background	123
proof_app_foreground	123
proof_native_radio-bounce-start	7
proof_native_radio-off	7
proof_native_radio-on	7
proof_no_validated_physical_fallback_inspections	2
proof_original_wifi_fingerprint	aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
proof_restored_wifi_fingerprint	aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
proof_fresh_dns_query	12345678-1234-1234-1234-123456789abc.wireguard-exit.nvpn-e2e.test
proof_wireguard_payload_label	radio-on
EOF
python3 - "$network_evidence" "$temp/android-marker-proof.tsv" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("network_evidence", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
path = pathlib.Path(sys.argv[2])
proof = module.validate_android_underlay_markers(path)
assert proof["noValidatedPhysicalFallbackEvidenceCount"] == 2
for old, new in (
    ("proof_no_validated_physical_fallback_inspections\t2",
     "proof_no_validated_physical_fallback_inspections\t1"),
    ("proof_restored_wifi_fingerprint\taaaa",
     "proof_restored_wifi_fingerprint\tbbbb"),
    ("proof_app_radio-off\t123", "proof_app_radio-off\t0"),
    ("proof_native_radio-off\t7\n", ""),
    ("12345678-1234-1234-1234-123456789abc.",
     "------------------------------------."),
):
    invalid_path = path.with_name("invalid-proof.tsv")
    invalid_path.write_text(
        path.read_text(encoding="utf-8").replace(old, new),
        encoding="utf-8",
    )
    try:
        module.validate_android_underlay_markers(invalid_path)
    except ValueError:
        pass
    else:
        raise SystemExit("Android marker proof accepted invalid evidence")
missing = path.with_name("missing-proof.tsv")
try:
    module.validate_android_underlay_markers(missing)
except ValueError:
    pass
else:
    raise SystemExit("Android platform proof accepted a missing receipt")
PY

python3 - "$android_lib" "$android_service" "$ios_underlay" "$ios_test" \
  "$ROOT/scripts/mobile-underlay-local-timestamp.py" <<'PY'
import pathlib
import sys

android, android_service, ios, ios_test, timestamp = (
    pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
)
if "except PermissionError:" not in timestamp or "child.terminate()" not in timestamp:
    raise SystemExit("continuity owner does not recover from process-group EPERM")
for forbidden in (
    "ALTERNATE_SSID",
    "ALTERNATE_SECURITY",
    "connect-network",
    "managed_ap",
    "for cycle in 1 2",
):
    if forbidden in android + ios + ios_test:
        raise SystemExit(f"Android radio-bounce gate retained obsolete topology: {forbidden}")
for required in (
    "shell svc wifi disable",
    "shell svc wifi enable",
    "try setWiFiEnabled(false)",
    "try setWiFiEnabled(true)",
    "let toggle = try openWiFiSettings(settings)",
    "persistOriginalWiFiForCleanup(originalSsid)",
    "hasOriginalWiFiForCleanup()",
    "originalWiFiForCleanup()",
):
    if required not in android + ios + ios_test:
        raise SystemExit(f"radio-bounce implementation is missing {required}")
if 'navigationBars["Wi-Fi"]' in ios:
    raise SystemExit("iOS Wi-Fi navigation still depends on a localized page title")
navigation = ios[ios.index("func openWiFiSettings") : ios.index("func wifiCellIsSelected")]
compact_navigation = "".join(navigation.split())
for required in (
    "normalizeSettingsRoot(settings)",
    "guard rows.count == 1",
    'row.staticTexts["Wi-Fi"].firstMatch',
    "settings.navigationBars.buttons.firstMatch",
    "settings.switches.allElementsBoundByIndex",
    "settings.descendants(matching: .any)",
    "binaryControlState(element) != nil",
    "binaryControls.count == 1",
):
    if required not in navigation:
        raise SystemExit(
            f"iOS Settings Wi-Fi navigation is not deterministic: missing {required}"
        )
if 'settings.cells.containing(.staticText,identifier:"Wi-Fi")' not in compact_navigation:
    raise SystemExit("iOS Settings does not select its unique public Wi-Fi row")
if 'settings.switches["Wi-Fi"]' in navigation:
    raise SystemExit("iOS Settings still assumes the destination switch is named Wi-Fi")
if "App-Prefs:" in navigation or "prefs:" in navigation.lower():
    raise SystemExit("iOS Settings navigation uses a private Settings URL")
if "for _ in 0..<5" in navigation:
    raise SystemExit("iOS Settings Wi-Fi navigation retained its fallback retry maze")
if "rows.count == 0" in navigation:
    raise SystemExit("iOS Wi-Fi page detection still rejects the Settings sidebar")
cleanup = ios_test[ios_test.index("func testReleaseDisconnectCleanup()") :]
for required in (
    "if let spec = optionalReleaseSpec(), spec.exerciseUnderlay",
    "try setWiFiEnabled(true)",
    "waitForPhysicalPath(",
    "if hasOriginalWiFiForCleanup()",
    "NVPN_IOS_RELEASE_HOME_WIFI_RESTORED=1",
    "NVPN_IOS_RELEASE_HOME_WIFI_ENABLED_NO_SAVED_SSID=1",
):
    if required not in cleanup:
        raise SystemExit(f"iOS cleanup lacks safe underlay restoration: {required}")
if "spec.exerciseUnderlay && hasOriginalWiFiForCleanup()" in cleanup:
    raise SystemExit("iOS cleanup skips Wi-Fi restoration without a saved SSID")
if cleanup.index("try setWiFiEnabled(true)") > cleanup.index(
    "if hasOriginalWiFiForCleanup()"
):
    raise SystemExit("iOS cleanup checks saved state before enabling Wi-Fi")
gate = android[android.index("run_android_underlay_network_change_gate()") :]
ordered = [gate.index(needle) for needle in (
    'recovery_requested_ms="$(mobile_underlay_now_ms)"',
    'shell svc wifi enable', 'android_underlay_wait_validated',
    'underlay_validated_ms="$(mobile_underlay_now_ms)"',
    'android_underlay_recovery_payloads')]
if ordered != sorted(ordered):
    raise SystemExit("Android radio-on and validated product clocks are not distinct")
payloads = android[
    android.index("android_underlay_recovery_payloads()"):
    android.index("android_vpn_service_log_count()")
]
ordered = [payloads.index(needle) for needle in (
    'dns_completion_ms="$(mobile_underlay_now_ms)"',
    'dns_recovery_ms=$((dns_completion_ms - underlay_validated_ms))',
    '--udp-echo',
    '\n  completion_ms="$(mobile_underlay_now_ms)"')]
if ordered != sorted(ordered):
    raise SystemExit(
        "Android recovery clock includes the later UDP evidence probe"
    )
fingerprint = android_service[
    android_service.index("private fun currentUnderlyingNetworkFingerprint("):
    android_service.index("private fun underlyingNetworkCandidate(")
]
if "NET_CAPABILITY_VALIDATED" not in fingerprint:
    raise SystemExit(
        "Android underlay fingerprint suppresses the route-ready to validated refresh"
    )
gate = ios[ios.index("SWITCH_1_NO_VALIDATED_PHYSICAL_FALLBACK") :]
ordered = [gate.index(needle) for needle in (
    'SWITCH_1_RECOVERY_REQUESTED_MS=', 'try setWiFiEnabled(true)',
    'SWITCH_1_UNDERLAY_VALIDATED_MS=', 'exerciseFreshDNSQuery')]
if ordered != sorted(ordered):
    raise SystemExit("iOS radio-on and validated product clocks are not distinct")
PY
[[ ! -e "$ROOT/scripts/lib-mobile-ios-hotspot.sh" ]] \
  && [[ ! -e "$ROOT/scripts/lib-mobile-android-managed-ap.sh" ]] \
  || { echo "obsolete hotspot/managed-AP libraries still exist" >&2; exit 1; }
if grep -Eq 'hotspot|ALTERNATE_(SSID|SECURITY|PASSPHRASE)|managed_ap' \
    "$mobile_exit_gate" "$release_gate" "$android_lib" "$ios_underlay"
then
  echo "mobile radio-bounce gate retained alternate-network/hotspot machinery" >&2
  exit 1
fi
grep -Fq 'wifi-radio-off-on-recovery' "$release_gate" \
  || { echo "release gate does not require the honest radio-bounce label" >&2; exit 1; }

echo "Mobile physical Wi-Fi radio off/on harness passed"
