#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ $# != 1 || ! -f "$1" ]]; then
  echo 'Usage: scripts/test-ios-private-exit.sh PAIRED_PROVIDER_SPEC.json' >&2
  exit 2
fi
source "$ROOT/scripts/release_common.sh"
source "$ROOT/scripts/mobile_env.sh"
source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
load_release_env "$ROOT"
load_mobile_env "$ROOT"
resolve_shared_build_metadata "$ROOT"
IOS_BUNDLE_ID="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
device="$(ios_release_network_resolve_device "${NVPN_IOS_DEVICE:?Select the paired test iPhone}")"
spec="$(python3 - "$1" <<'PY'
import base64, ipaddress, json, re, sys, urllib.parse
from pathlib import Path
s = json.loads(Path(sys.argv[1]).read_bytes())
url = urllib.parse.urlsplit(s["probeURL"])
if not (re.fullmatch(r"npub1[023456789acdefghjklmnpqrstuvwxyz]{58}", s["providerNpub"])
        and re.fullmatch(r"[0-9a-f]{32}", s["challenge"])
        and url.scheme == "http" and url.hostname and url.username is None
        and url.password is None and not url.fragment and url.query == s["challenge"]
        and ipaddress.ip_address(url.hostname) in ipaddress.ip_network("198.18.0.0/15")
        and 0 < (url.port or 80) <= 65535
        and type(s.get("restoreInterruptedSelection", False)) is bool):
    sys.exit("Invalid controlled private-exit fixture")
print(base64.b64encode(json.dumps(s).encode()).decode())
PY
)"
root="${NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR:-$ROOT/artifacts/mobile-ios}"
mkdir -p "$root"
out="$(mktemp -d "$root/private-exit.XXXXXX")"
export NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR="$out"
export NVPN_MOBILE_WG_EXIT_REUSE_IOS_BUILD=1 NVPN_MOBILE_WG_EXIT_INSTALL_IOS=0
ios_release_network_require_unlocked "$device"
ios_release_network_prepare "$device"
run_ui() {
  local label="$1" method="$2" settings="$3" id="$4" rc=0
  local log="$out/$label.log" result="$out/$label.xcresult"
  ios_release_network_prepare_xctestrun "$label" "$settings" "$id" || return 1
  ios_release_network_test_command "$IOS_RELEASE_NETWORK_CASE_XCTESTRUN" || return 1
  ios_release_network_register_diagnostics "$settings" "$log" "$result"
  ios_release_network_run_bounded_xcode "$label" 420 180 NVPN_XCUITEST_STARTED=1 \
    "$id" "$log" "$out/$label-host-markers.tsv" "$device" "" \
    "${IOS_RELEASE_NETWORK_XCODE_COMMAND[@]}" -resultBundlePath "$result" \
    "-only-testing:NostrVpnIosUITests/NostrVpnReleaseNetworkUITests/$method" \
    test-without-building || rc=$?
  ios_release_network_delete_private_test_products || return 1
  ios_release_network_preserve_pending_diagnostics || return 1
  (( rc == 0 )) || return "$rc"
  ios_release_network_collect_markers "$log" "$id" "$out/$label-markers.log"
}
run_id="$(uuidgen)"
cleanup() {
  local rc=$? state recovery
  trap - EXIT INT TERM HUP
  set +e
  if (( rc != 0 )) && [[ -f "$out/test.log" ]]; then
    # Only recover after this exact test observed the original state and armed a UI mutation.
    state="$(awk -v context="NVPN_XCUITEST_RUN_ID=$run_id" '
      {sub(/\r$/, "")}
      previous==context && /^NVPN_IOS_PRIVATE_EXIT_RESTORE_VPN_ON=[01]$/ {print substr($0,length($0))}
      {previous=$0}
    ' "$out/test.log" | sort -u)"
    if [[ "$state" == 0 || "$state" == 1 ]]; then
      if [[ "$state" == 1 ]]; then state=true; else state=false; fi
      recovery="$(printf '{"restoreVPNOn":%s}' "$state" | base64 | tr -d '\n')"
      ios_release_network_abort_active_run
      ios_release_network_delete_private_test_products
      run_ui restore testRestoreInterruptedPrivateExit "$recovery" "$(uuidgen)" || rc=1
      grep -Fxq NVPN_IOS_PRIVATE_EXIT_RECOVERED=1 "$out/restore-markers.log" || rc=1
    fi
  fi
  ios_release_network_cleanup_private_artifacts || rc=1
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 143' TERM HUP
trap 'exit 130' INT
run_ui test testReleasePrivateExit "$spec" "$run_id"
for marker in VISIBLE TRAFFIC_VERIFIED DIRECT_RESTORED; do
  [[ "$(grep -Fxc "NVPN_IOS_PRIVATE_EXIT_${marker}=1" "$out/test-markers.log")" == 1 ]]
done
echo "Verified private provider discovery, traffic and restoration"
