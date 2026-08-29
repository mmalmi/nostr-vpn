#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/mobile-wireguard-exit-e2e.sh"
FIXTURE_LIB="$ROOT/scripts/lib-mobile-wireguard-fixture.sh"
TLS_COUNTER="$ROOT/scripts/mobile-wireguard-tls-sni-count.py"
FIXTURE_SERVER="$ROOT/scripts/mobile-wireguard-exit-server.sh"
HARNESS_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-mobile-wg-contract.XXXXXX")"

cleanup_harness() {
  rm -rf "$HARNESS_ROOT"
}
trap cleanup_harness EXIT

fail() {
  echo "$*" >&2
  exit 1
}

assert_count() {
  local expected="$1" pattern="$2" path="$3" actual
  actual="$(grep -Fc -- "$pattern" "$path" || true)"
  [[ "$actual" -eq "$expected" ]] \
    || fail "$path contains $actual copies of '$pattern'; expected $expected"
}

grep -Fq 'tc filter add dev wg0 egress matchall action csum tcp udp' \
  "$FIXTURE_SERVER" \
  || fail "Docker fixture no longer finalizes forwarded WireGuard checksums"

# Exercise the shared production fixture contract directly. The physical gate
# remains responsible for proving the device packet paths; this harness only
# checks deterministic mapping, validation, and exclusive counter semantics.
# shellcheck disable=SC1090
source "$FIXTURE_LIB"

cases=(
  automatic-profile
  cloudflare-doh
  quad9-doh
  custom-doh
  through-exit
)
mobile_wg_dns_cases_are_complete "${cases[@]}" \
  || fail "canonical five-case DNS matrix was rejected"
if mobile_wg_dns_cases_are_complete "${cases[@]:0:4}"; then
  fail "partial DNS matrix was accepted as canonical"
fi

actual_case_fields=""
for label in "${cases[@]}"; do
  actual_case_fields+="$label|$(
    mobile_wg_dns_case_fields \
      "$label" fixture.nvpn.test 10.99.77.1 10.99.77.53
  )"$'\n'
done
expected_case_fields=$'automatic-profile|automatic|cloudflare||||fixture.nvpn.test|10.99.77.1|dns-profile\ncloudflare-doh|encrypted|cloudflare||||cloudflare.192-0-43-8.sslip.io|192.0.43.8|doh-cloudflare\nquad9-doh|encrypted|quad9||||quad9.192-0-43-8.sslip.io|192.0.43.8|doh-quad9\ncustom-doh|encrypted|custom|https://dns.google/dns-query|8.8.8.8||custom.192-0-43-8.sslip.io|192.0.43.8|doh-google\nthrough-exit|through_exit|cloudflare|||10.99.77.53|through-exit.fixture.nvpn.test|10.99.77.1|dns-through\n'
[[ "$actual_case_fields" == "$expected_case_fields" ]] \
  || fail "production DNS case mapping changed"

for endpoint in \
  $'192.0.2.10|51820|ipv4\t192.0.2.10\t192.0.2.10:51820' \
  $'fixture.example.test|51820|dns\tfixture.example.test\tfixture.example.test:51820' \
  $'2001:db8::10|51820|ipv6\t2001:db8::10\t[2001:db8::10]:51820'
do
  IFS='|' read -r host port expected <<<"$endpoint"
  [[ "$(mobile_wg_endpoint_fields "$host" "$port")" == "$expected" ]] \
    || fail "valid endpoint was rendered incorrectly: $host"
done
for host in \
  "" " fixture.example.test" "fixture.example.test " \
  "[2001:db8::10]" "fixture.example.test:51820" \
  "https://fixture.example.test" "fixture.example.test/path" \
  "2001:db8::gg" "-fixture.example.test" "fixture..example.test" \
  "999.2.3.4"
do
  if mobile_wg_endpoint_fields "$host" 51820 >/dev/null 2>&1; then
    fail "malformed endpoint host was accepted: '$host'"
  fi
done
for port in 0 65536 port; do
  if mobile_wg_endpoint_fields fixture.example.test "$port" >/dev/null 2>&1; then
    fail "malformed endpoint port was accepted: '$port'"
  fi
done

for evidence_case in \
  $'automatic-profile|dns-profile|0\t0\t0\t0\t0\t0\t0|1\t1\t0\t0\t0\t0\t0' \
  $'cloudflare-doh|doh-cloudflare|0\t0\t0\t0\t0\t0\t0|0\t0\t1\t0\t0\t0\t0' \
  $'quad9-doh|doh-quad9|0\t0\t0\t0\t0\t0\t0|0\t0\t0\t1\t0\t0\t0' \
  $'custom-doh|doh-google|0\t0\t0\t0\t0\t0\t0|0\t0\t0\t0\t1\t0\t0' \
  $'through-exit|dns-through|0\t0\t0\t0\t0\t0\t0|1\t0\t0\t0\t0\t1\t0'
do
  IFS='|' read -r label evidence before after <<<"$evidence_case"
  mobile_wg_fixture_assert_timed_dns_case_evidence \
    Android "$label" "$evidence" \
    $'1000\t'"$before" $'1001\t'"$after" >/dev/null \
    || fail "valid $label DNS evidence was rejected"
done
if mobile_wg_fixture_assert_timed_dns_case_evidence \
    Android cloudflare-doh doh-cloudflare \
    $'1000\t0\t0\t0\t0\t0\t0\t0' \
    $'1001\t1\t0\t1\t0\t0\t0\t0' >/dev/null 2>&1
then
  fail "encrypted DNS accepted a plaintext fallback"
fi
if mobile_wg_fixture_assert_timed_dns_case_evidence \
    Android automatic-profile dns-profile \
    $'1001\t0\t0\t0\t0\t0\t0\t0' \
    $'1000\t1\t1\t0\t0\t0\t0\t0' >/dev/null 2>&1
then
  fail "DNS evidence accepted a reversed observation window"
fi

# Keep one executable parser regression for fragmented resolver ClientHello
# traffic; static greps cannot prove the fixture's SNI evidence parser works.
python3 - "$TLS_COUNTER" <<'PY'
import runpy
import struct
import sys

parse = runpy.run_path(sys.argv[1])["client_hello_snis"]
name = b"cloudflare-dns.com"
server_name = b"\x00" + len(name).to_bytes(2, "big") + name
value = len(server_name).to_bytes(2, "big") + server_name
extension = b"\x00\x00" + len(value).to_bytes(2, "big") + value
hello = (
    b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01"
    + b"\x01\x00" + len(extension).to_bytes(2, "big") + extension
)
handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
assert parse(record) == [name.decode()]
assert parse(b"ordinary HTTPS bytes: " + name) == []
PY

grep -Fq 'NVPN_ANDROID_RELEASE_DNS_ONLY_CYCLE="$((1 - first))"' \
  "$ROOT/scripts/mobile-wireguard-exit-e2e.sh" \
  || fail "Android follow-up DNS cases do not reuse the proven WireGuard setup"
grep -Fq 'if ! truthy "$ANDROID_RELEASE_DNS_ONLY_CYCLE"; then' \
  "$ROOT/scripts/lib-mobile-android-release-gate.sh" \
  || fail "Android Release gate lacks its focused follow-up DNS path"

MOCK_ROOT="$HARNESS_ROOT/root"
MOCK_BIN="$HARNESS_ROOT/bin"
mkdir -p "$MOCK_ROOT/scripts" "$MOCK_BIN"
cp "$GATE" "$MOCK_ROOT/scripts/mobile-wireguard-exit-e2e.sh"
chmod +x "$MOCK_ROOT/scripts/mobile-wireguard-exit-e2e.sh"

cat >"$MOCK_ROOT/scripts/release_common.sh" <<'SH'
#!/usr/bin/env bash
bool_is_true() {
  case "${1:-}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
    *) return 1 ;;
  esac
}
load_release_env() { :; }
load_appstoreconnect_defaults() { :; }
resolve_shared_build_metadata() {
  printf 'build-metadata %s\n' "$1" >>"$NVPN_CONTRACT_EVENTS"
}
SH

cat >"$MOCK_ROOT/scripts/mobile_env.sh" <<'SH'
#!/usr/bin/env bash
load_mobile_env() { :; }
select_physical_android_serial() { printf '%s\n' "${2:-android-physical}"; }
select_physical_ios_device() { printf '%s\n' "$1"; }
SH

cat >"$MOCK_ROOT/scripts/lib-mobile-underlay-change.sh" <<'SH'
#!/usr/bin/env bash
mobile_continuity_stop() {
  printf 'continuity-stop\n' >>"$NVPN_CONTRACT_EVENTS"
}
SH

cat >"$MOCK_ROOT/scripts/lib-mobile-wireguard-fixture.sh" <<'SH'
#!/usr/bin/env bash
# shellcheck disable=SC1090
source "$NVPN_WG_REAL_FIXTURE_LIB"

mock_increment() {
  local path="$1" value=0
  [[ ! -f "$path" ]] || value="$(<"$path")"
  value=$((value + 1))
  printf '%s\n' "$value" >"$path"
  printf '%s\n' "$value"
}

mobile_wg_fixture_initialize() {
  MOBILE_WG_FIXTURE_VOLUME_DIR="$2"
  printf 'fixture-init %s\n' "$2" >>"$NVPN_CONTRACT_EVENTS"
}
mobile_wg_fixture_assert_available() { :; }
mobile_wg_fixture_build() {
  printf 'fixture-build %s %s\n' "$2" "$3" >>"$NVPN_CONTRACT_EVENTS"
}
mobile_wg_fixture_run() {
  MOBILE_WG_FIXTURE_STARTED=1
  printf 'fixture-run %s\n' "$2" >>"$NVPN_CONTRACT_EVENTS"
}
mobile_wg_fixture_ready() { return 0; }
mobile_wg_fixture_running() { return 0; }
mobile_wg_fixture_logs() { :; }
mobile_wg_fixture_wg_bytes() {
  local value
  value="$(mock_increment "$NVPN_CONTRACT_STATE/wg")"
  printf '%s\t%s\n' "$value" "$value"
}
mobile_wg_fixture_forward_packets() {
  mock_increment "$NVPN_CONTRACT_STATE/forward"
}
mobile_wg_fixture_timed_dns_evidence_snapshot() {
  local unused_container="$1" host="$2" call after=0 timestamp
  local key="${host//[^A-Za-z0-9]/_}"
  call="$(mock_increment "$NVPN_CONTRACT_STATE/dns-$key")"
  timestamp="$(mock_increment "$NVPN_CONTRACT_STATE/time")"
  ((call % 2 == 0)) && after=1
  case "$host" in
    wireguard-exit.nvpn-e2e.test)
      printf '%s\t%s\t%s\t0\t0\t0\t0\t0\n' \
        "$timestamp" "$after" "$after"
      ;;
    cloudflare.*)
      printf '%s\t0\t0\t%s\t0\t0\t0\t0\n' "$timestamp" "$after"
      ;;
    quad9.*)
      printf '%s\t0\t0\t0\t%s\t0\t0\t0\n' "$timestamp" "$after"
      ;;
    custom.*)
      printf '%s\t0\t0\t0\t0\t%s\t0\t0\n' "$timestamp" "$after"
      ;;
    through-exit.*)
      printf '%s\t%s\t0\t0\t0\t0\t%s\t0\n' \
        "$timestamp" "$after" "$after"
      ;;
    *) return 2 ;;
  esac
}
mobile_wg_fixture_dns_count() { printf '1\n'; }
mobile_wg_fixture_begin_cleanup() {
  trap - EXIT
  trap '' HUP INT TERM
  printf 'fixture-begin-cleanup\n' >>"$NVPN_CONTRACT_EVENTS"
}
mobile_wg_fixture_cleanup() {
  printf 'fixture-cleanup %s\n' "$1" >>"$NVPN_CONTRACT_EVENTS"
  [[ "${NVPN_CONTRACT_CLEANUP_FAIL:-0}" != 1 ]]
}
SH

cat >"$MOCK_ROOT/scripts/lib-mobile-ios-release-network.sh" <<'SH'
#!/usr/bin/env bash
ios_release_network_prepare() {
  printf 'ios-prepare %s\n' "$1" >>"$NVPN_CONTRACT_EVENTS"
}
ios_release_network_disconnect_cleanup() {
  printf 'ios-disconnect-cleanup %s\n' "${1:-0}" >>"$NVPN_CONTRACT_EVENTS"
}
ios_release_network_cleanup_private_artifacts() {
  printf 'ios-private-cleanup\n' >>"$NVPN_CONTRACT_EVENTS"
}
run_ios_release_network_case() {
  local label="$1" run_id="$2" spec="$3"
  python3 - "$NVPN_CONTRACT_IOS_CASES" "$label" "$run_id" "$spec" \
    "$4" "$5" "$6" "$7" <<'PY'
import base64
import json
import pathlib
import sys

path, label, run_id, encoded, lifecycle, underlay, direct, rapid = sys.argv[1:]
payload = json.loads(base64.b64decode(encoded))
record = {
    "label": label,
    "runId": run_id,
    "lifecycleArg": lifecycle,
    "underlayArg": underlay,
    "directArg": direct,
    "rapidArg": rapid,
    "spec": payload,
}
with pathlib.Path(path).open("a", encoding="utf-8") as output:
    output.write(json.dumps(record, sort_keys=True) + "\n")
PY
  if bool_is_true "$5"; then
    mkdir -p "$NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR"
    printf '%s\n' \
      'NVPN_IOS_UNDERLAY_SWITCH_1_FRESH_DNS_QUERY=12345678-1234-1234-1234-123456789abc.fixture.test' \
      >"$NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR/mobile-ios-release-network-automatic-profile-contract-runner-markers.log"
  fi
  [[ "${NVPN_CONTRACT_FAIL_IOS_LABEL:-}" != "$label" ]]
}
SH

cat >"$MOCK_ROOT/scripts/mobile-android-smoke.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
python3 - "$NVPN_CONTRACT_ANDROID_CASES" "$@" <<'PY'
import json
import os
import pathlib
import sys

mode = os.environ["NVPN_ANDROID_EXIT_DNS_MODE"]
provider = os.environ["NVPN_ANDROID_EXIT_DNS_DOH_PROVIDER"]
label = {
    ("automatic", "cloudflare"): "automatic-profile",
    ("encrypted", "cloudflare"): "cloudflare-doh",
    ("encrypted", "quad9"): "quad9-doh",
    ("encrypted", "custom"): "custom-doh",
    ("through_exit", "cloudflare"): "through-exit",
}[(mode, provider)]
keys = (
    "NVPN_ANDROID_EXIT_DNS_MODE",
    "NVPN_ANDROID_EXIT_DNS_DOH_PROVIDER",
    "NVPN_ANDROID_EXIT_DNS_CUSTOM_DOH_URL",
    "NVPN_ANDROID_EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS",
    "NVPN_ANDROID_EXIT_DNS_THROUGH_EXIT_SERVERS",
    "NVPN_ANDROID_EXIT_DNS_USE_SHIPPED_UI",
    "NVPN_ANDROID_SWITCH_TO_DIRECT_WHILE_CONNECTED",
    "NVPN_ANDROID_LIFECYCLE_GATE",
    "NVPN_ANDROID_UNDERLAY_CHANGE_GATE",
    "NVPN_ANDROID_RAPID_START_STOP_GATE",
    "NVPN_ANDROID_EXPECT_WIREGUARD_ENDPOINT",
    "NVPN_ANDROID_EXPECTED_EXIT_SOURCE_IP",
)
record = {
    "label": label,
    "args": sys.argv[2:],
    **{key: os.environ.get(key, "") for key in keys},
}
with pathlib.Path(sys.argv[1]).open("a", encoding="utf-8") as output:
    output.write(json.dumps(record, sort_keys=True) + "\n")
PY
if [[ "${NVPN_ANDROID_UNDERLAY_CHANGE_GATE:-0}" == 1 ]]; then
  mkdir -p "$NVPN_ANDROID_RESULT_DIR"
  printf 'proof_fresh_dns_query\t%s\n' \
    '12345678-1234-1234-1234-123456789abc.fixture.test' \
    >"$NVPN_ANDROID_RESULT_DIR/mobile-android-underlay-contract-markers.tsv"
fi
mode="${NVPN_ANDROID_EXIT_DNS_MODE}"
provider="${NVPN_ANDROID_EXIT_DNS_DOH_PROVIDER}"
label="$mode-$provider"
case "$label" in
  automatic-cloudflare) label=automatic-profile ;;
  encrypted-cloudflare) label=cloudflare-doh ;;
  encrypted-quad9) label=quad9-doh ;;
  encrypted-custom) label=custom-doh ;;
  through_exit-cloudflare) label=through-exit ;;
esac
[[ "${NVPN_CONTRACT_FAIL_ANDROID_LABEL:-}" != "$label" ]]
SH
chmod +x "$MOCK_ROOT/scripts/mobile-android-smoke.sh"

cat >"$MOCK_ROOT/scripts/release-network-evidence.py" <<'PY'
import json
import os
import pathlib
import sys

args = sys.argv[1:]
if not args or args[0] != "mobile":
    raise SystemExit("expected mobile evidence mode")

def value(flag):
    return args[args.index(flag) + 1]

artifact = pathlib.Path(value("--artifact-receipt"))
ledger = pathlib.Path(value("--counter-ledger"))
output = pathlib.Path(value("--output"))
if not artifact.is_file():
    raise SystemExit("exact artifact receipt is missing")
if not ledger.is_file() or not ledger.read_text(encoding="utf-8").strip():
    raise SystemExit("durable counter ledger is missing")
record = {
    "platform": value("--platform"),
    "mode": value("--mode"),
    "artifactReceipt": str(artifact),
    "counterLedger": str(ledger),
    "output": str(output),
    "includeUnderlay": "--include-underlay-lifecycle" in args,
}
with pathlib.Path(os.environ["NVPN_CONTRACT_EVIDENCE_LOG"]).open(
    "a", encoding="utf-8"
) as log:
    log.write(json.dumps(record, sort_keys=True) + "\n")
output.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
PY

cat >"$MOCK_BIN/wg" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  genkey) printf 'private-key\n' ;;
  pubkey) read -r _ || true; printf 'public-key\n' ;;
  *) exit 2 ;;
esac
SH
cat >"$MOCK_BIN/adb" <<'SH'
#!/usr/bin/env bash
if [[ " $* " == *" devices "* ]]; then
  printf 'List of devices attached\nandroid-physical\tdevice\n'
elif [[ " $* " == *" shell pm list packages "* ]]; then
  printf 'package:fi.siriusbusiness.nvpn\n'
else
  exit 2
fi
SH
chmod +x "$MOCK_BIN/wg" "$MOCK_BIN/adb"

run_gate() {
  local name="$1" platform="$2" selected_cases="$3" underlay="$4"
  local fail_android="$5" fail_ios="$6" cleanup_fail="$7"
  local android_receipt="$8" ios_receipt="$9" expected_status="${10}"
  local status
  RUN_DIR="$HARNESS_ROOT/$name"
  mkdir -p \
    "$RUN_DIR/state" "$RUN_DIR/android-artifacts" "$RUN_DIR/ios-artifacts"
  : >"$RUN_DIR/events.log"
  : >"$RUN_DIR/android-cases.jsonl"
  : >"$RUN_DIR/ios-cases.jsonl"
  : >"$RUN_DIR/evidence.jsonl"
  [[ "$android_receipt" != 1 ]] \
    || printf '{"artifact":"android"}\n' >"$RUN_DIR/android-artifact.json"
  [[ "$ios_receipt" != 1 ]] \
    || printf '{"artifact":"ios"}\n' >"$RUN_DIR/ios-artifact.json"

  set +e
  env \
    PATH="$MOCK_BIN:$PATH" \
    NVPN_RELEASE_ENV_FILE="$RUN_DIR/no-release-env" \
    NVPN_MOBILE_ENV_FILE="$RUN_DIR/no-mobile-env" \
    NVPN_WG_REAL_FIXTURE_LIB="$FIXTURE_LIB" \
    NVPN_CONTRACT_STATE="$RUN_DIR/state" \
    NVPN_CONTRACT_EVENTS="$RUN_DIR/events.log" \
    NVPN_CONTRACT_ANDROID_CASES="$RUN_DIR/android-cases.jsonl" \
    NVPN_CONTRACT_IOS_CASES="$RUN_DIR/ios-cases.jsonl" \
    NVPN_CONTRACT_EVIDENCE_LOG="$RUN_DIR/evidence.jsonl" \
    NVPN_CONTRACT_FAIL_ANDROID_LABEL="$fail_android" \
    NVPN_CONTRACT_FAIL_IOS_LABEL="$fail_ios" \
    NVPN_CONTRACT_CLEANUP_FAIL="$cleanup_fail" \
    NVPN_MOBILE_WG_EXIT_HOST_IP=192.0.2.10 \
    NVPN_MOBILE_WG_EXIT_EXPECTED_SOURCE_IP=203.0.113.8 \
    NVPN_MOBILE_WG_EXIT_IMAGE_READY=1 \
    NVPN_MOBILE_WG_EXIT_DNS_CASES="$selected_cases" \
    NVPN_MOBILE_WG_EXIT_LIFECYCLE_GATE=1 \
    NVPN_MOBILE_WG_EXIT_UNDERLAY_CHANGE_GATE="$underlay" \
    NVPN_MOBILE_WG_EXIT_RAPID_START_STOP_GATE=auto \
    NVPN_MOBILE_WG_EXIT_REUSE_ANDROID_BUILD=1 \
    NVPN_MOBILE_WG_EXIT_INSTALL_ANDROID=0 \
    NVPN_ANDROID_SERIAL=android-physical \
    NVPN_ANDROID_RESULT_DIR="$RUN_DIR/android-artifacts" \
    NVPN_MOBILE_ANDROID_RELEASE_RECEIPT="$RUN_DIR/android-artifact.json" \
    NVPN_MOBILE_ANDROID_NETWORK_EVIDENCE_OUTPUT="$RUN_DIR/android-network.json" \
    NVPN_IOS_DEVICE=ios-physical \
    NVPN_IOS_EXPECTED_DEVICE_NAME='Contract iPhone' \
    NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR="$RUN_DIR/ios-artifacts" \
    NVPN_MOBILE_IOS_RELEASE_RECEIPT="$RUN_DIR/ios-artifact.json" \
    NVPN_MOBILE_IOS_NETWORK_EVIDENCE_OUTPUT="$RUN_DIR/ios-network.json" \
    "$MOCK_ROOT/scripts/mobile-wireguard-exit-e2e.sh" "$platform" \
    >"$RUN_DIR/stdout.log" 2>"$RUN_DIR/stderr.log"
  status=$?
  set -e
  [[ "$status" -eq "$expected_status" ]] || {
    sed -n '1,160p' "$RUN_DIR/stderr.log" >&2
    fail "$name exited $status; expected $expected_status"
  }
}

assert_fixture_cleaned() {
  local run="$1" fixture_dir
  assert_count 1 'fixture-cleanup ' "$run/events.log"
  fixture_dir="$(sed -n 's/^fixture-init //p' "$run/events.log")"
  [[ -n "$fixture_dir" && ! -e "$fixture_dir" ]] \
    || fail "fixture private directory survived cleanup: $fixture_dir"
}

run_gate full all "" 0 "" "" 0 1 1 0
python3 - "$RUN_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
android = [json.loads(line) for line in (root / "android-cases.jsonl").read_text().splitlines()]
ios = [json.loads(line) for line in (root / "ios-cases.jsonl").read_text().splitlines()]
labels = [
    "automatic-profile", "cloudflare-doh", "quad9-doh", "custom-doh", "through-exit"
]
assert [case["label"] for case in android] == labels
assert [case["label"] for case in ios] == labels
expected = [
    ("automatic", "cloudflare", "", "", ""),
    ("encrypted", "cloudflare", "", "", ""),
    ("encrypted", "quad9", "", "", ""),
    ("encrypted", "custom", "https://dns.google/dns-query", "8.8.8.8", ""),
    ("through_exit", "cloudflare", "", "", "10.99.77.53"),
]
for index, (case, values) in enumerate(zip(android, expected)):
    keys = (
        "NVPN_ANDROID_EXIT_DNS_MODE",
        "NVPN_ANDROID_EXIT_DNS_DOH_PROVIDER",
        "NVPN_ANDROID_EXIT_DNS_CUSTOM_DOH_URL",
        "NVPN_ANDROID_EXIT_DNS_CUSTOM_DOH_BOOTSTRAP_IPS",
        "NVPN_ANDROID_EXIT_DNS_THROUGH_EXIT_SERVERS",
    )
    assert tuple(case[key] for key in keys) == values
    assert case["NVPN_ANDROID_EXIT_DNS_USE_SHIPPED_UI"] == "1"
    assert case["NVPN_ANDROID_EXPECT_WIREGUARD_ENDPOINT"] == "192.0.2.10:51886"
    assert case["NVPN_ANDROID_EXPECTED_EXIT_SOURCE_IP"] == "203.0.113.8"
    assert case["NVPN_ANDROID_LIFECYCLE_GATE"] == ("1" if index == 0 else "false")
    assert case["NVPN_ANDROID_RAPID_START_STOP_GATE"] == ("1" if index == 0 else "0")
    assert case["NVPN_ANDROID_SWITCH_TO_DIRECT_WHILE_CONNECTED"] == ("1" if index == 4 else "0")
    assert "--release-network-gate" in case["args"]
    assert "--no-build" in case["args"] and "--no-install" in case["args"]
    assert ("--create-network" in case["args"]) == (index == 0)
for index, case in enumerate(ios):
    spec = case["spec"]
    mode, provider, custom, bootstrap, through = expected[index]
    assert (spec["mode"], spec["provider"], spec["customUrl"], spec["bootstrapIps"], spec["throughExitServers"]) == expected[index]
    assert spec["createNetwork"] == (index == 0)
    assert spec["exerciseLifecycle"] == (index == 0)
    assert spec["exerciseStartStopStress"] == (index == 0)
    assert spec["exerciseUnderlay"] is False
    assert spec["switchToDirect"] == (index == 4)
    assert case["lifecycleArg"] == ("1" if index == 0 else "false")
    assert case["directArg"] == ("1" if index == 4 else "0")
evidence = [json.loads(line) for line in (root / "evidence.jsonl").read_text().splitlines()]
assert {(item["platform"], item["mode"]) for item in evidence} == {
    ("android", "wireguard-dns"), ("ios", "wireguard-dns")
}
assert all(item["includeUnderlay"] is False for item in evidence)
assert all(pathlib.Path(item["artifactReceipt"]).is_file() for item in evidence)
assert (root / "android-network.json").is_file()
assert (root / "ios-network.json").is_file()
PY
assert_fixture_cleaned "$RUN_DIR"
assert_count 1 'ios-prepare ' "$RUN_DIR/events.log"
assert_count 2 'ios-disconnect-cleanup ' "$RUN_DIR/events.log"
assert_count 1 'ios-private-cleanup' "$RUN_DIR/events.log"

run_gate underlay all automatic-profile 1 "" "" 0 1 1 0
python3 - "$RUN_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
android = json.loads((root / "android-cases.jsonl").read_text())
ios = json.loads((root / "ios-cases.jsonl").read_text())
assert android["NVPN_ANDROID_UNDERLAY_CHANGE_GATE"] == "1"
assert android["NVPN_ANDROID_LIFECYCLE_GATE"] == "1"
assert android["NVPN_ANDROID_SWITCH_TO_DIRECT_WHILE_CONNECTED"] == "0"
assert ios["spec"]["exerciseUnderlay"] is True
assert ios["spec"]["exerciseLifecycle"] is True
assert ios["spec"]["switchToDirect"] is True
assert (root / "android-artifacts/mobile-android-underlay-fresh-dns-fixture.json").is_file()
assert (root / "ios-artifacts/mobile-ios-underlay-fresh-dns-fixture.json").is_file()
evidence = [json.loads(line) for line in (root / "evidence.jsonl").read_text().splitlines()]
assert {(item["platform"], item["mode"]) for item in evidence} == {
    ("android", "underlay-lifecycle"), ("ios", "underlay-lifecycle")
}
assert all(item["includeUnderlay"] is False for item in evidence)
PY
assert_fixture_cleaned "$RUN_DIR"

run_gate focused-rapid-retry android automatic-profile 0 "" "" 0 1 0 0
python3 - "$RUN_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
android = json.loads((root / "android-cases.jsonl").read_text())
assert android["NVPN_ANDROID_RAPID_START_STOP_GATE"] == "1"
assert android["NVPN_ANDROID_SWITCH_TO_DIRECT_WHILE_CONNECTED"] == "0"
PY
assert_fixture_cleaned "$RUN_DIR"

run_gate android-failure android automatic-profile,cloudflare-doh 0 cloudflare-doh "" 0 1 0 1
assert_fixture_cleaned "$RUN_DIR"
retained_ledger="$(
  sed -n 's/^Android network counter ledger retained after incomplete receipt: //p' \
    "$RUN_DIR/stderr.log"
)"
[[ -f "$retained_ledger" && "$(wc -l <"$retained_ledger")" -eq 1 ]] \
  || fail "Android failure did not retain its one completed-case ledger"
rm -f "$retained_ledger"
[[ ! -e "$RUN_DIR/android-network.json" ]] \
  || fail "Android failure produced a canonical receipt"

# A failed platform run must leave the fixture clean enough for an independent
# platform run to succeed without rebuilding or mutating a device.
run_gate ios-after-android-failure ios automatic-profile 1 "" "" 0 0 1 0
assert_fixture_cleaned "$RUN_DIR"
[[ -s "$RUN_DIR/ios-network.json" ]] \
  || fail "iOS contract did not recover after isolated Android failure"

run_gate ios-failure ios automatic-profile,cloudflare-doh 0 "" cloudflare-doh 0 0 1 1
assert_fixture_cleaned "$RUN_DIR"
assert_count 2 'ios-disconnect-cleanup ' "$RUN_DIR/events.log"
assert_count 1 'ios-private-cleanup' "$RUN_DIR/events.log"
retained_ledger="$(
  sed -n 's/^iOS network counter ledger retained after incomplete receipt: //p' \
    "$RUN_DIR/stderr.log"
)"
[[ -f "$retained_ledger" && "$(wc -l <"$retained_ledger")" -eq 1 ]] \
  || fail "iOS failure did not retain its one completed-case ledger"
rm -f "$retained_ledger"

run_gate missing-artifact android automatic-profile 1 "" "" 0 0 0 1
grep -Fq 'exact artifact receipt is missing' "$RUN_DIR/stderr.log" \
  || fail "mobile gate accepted missing exact artifact receipt"
assert_fixture_cleaned "$RUN_DIR"
retained_ledger="$(
  sed -n 's/^Android network counter ledger retained after incomplete receipt: //p' \
    "$RUN_DIR/stderr.log"
)"
rm -f "$retained_ledger"

run_gate cleanup-failure android automatic-profile 1 "" "" 1 1 0 1
grep -Fq 'fixture cleanup left a managed resource behind' "$RUN_DIR/stderr.log" \
  || fail "successful gate ignored cleanup verification failure"
assert_fixture_cleaned "$RUN_DIR"

echo "mobile WireGuard exit DNS harness contract passed"
