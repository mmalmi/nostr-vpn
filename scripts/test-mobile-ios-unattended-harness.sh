#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/lib-mobile-ios-release-network.sh"
source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
private="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-unattended.XXXXXX")"
trap 'rm -rf "$private"' EXIT
mkdir "$private/bin"
cat >"$private/bin/xcrun" <<'PY'
#!/usr/bin/env python3
import json,os,sys,time
assert sys.argv[1:4]==['devicectl','--timeout','5']
assert sys.argv[4:7]==['device','info','lockState']
mode=os.environ['NVPN_TEST_LOCK_STATE']
if mode=='unavailable':sys.exit(1)
if mode=='timeout':time.sleep(30)
p=sys.argv[sys.argv.index('--json-output')+1]
json.dump({'result':{'passcodeRequired':mode=='locked'} if mode!='missing' else {}},open(p,'w'))
PY
chmod +x "$private/bin/xcrun"
export PATH="$private/bin:$PATH"
export NVPN_TEST_LOCK_STATE=unlocked
ios_release_network_require_unlocked fixture
for state in locked unavailable missing timeout; do
 export NVPN_TEST_LOCK_STATE="$state"
 if ios_release_network_require_unlocked fixture >"$private/$state.log" 2>&1; then
  echo "Physical preflight accepted $state" >&2;exit 1
 fi
done
# A locked phone must not launch a runner or arm device mutations.
export NVPN_TEST_LOCK_STATE=locked
RELEASE_JOIN_ARTIFACTS_VALIDATED=1
RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1
IOS_DEVICE=fixture
PRIVATE_DIR="$private"
release_join_ios_test_command() { echo launched >"$private/launched"; }
if release_join_ios_start_test fixture "$private/test.log"; then exit 1;fi
[[ ! -e "$private/launched" && "$RELEASE_JOIN_DEVICE_MUTATED" == 0 ]]
# With no test method and a freshly proven stopped baseline, failed startup
# cleanup must preserve that state without another UI automation session.
RELEASE_JOIN_IOS_CLEANUP_ARMED=1
RELEASE_JOIN_IOS_CLEANUP_BUNDLE_ID=fixture
RELEASE_JOIN_IOS_QUARANTINE="$private/quarantine"
RELEASE_JOIN_IOS_BASELINE_STOPPED=1
RELEASE_JOIN_IOS_METHOD_STARTED=0
RELEASE_JOIN_IOS_STARTUP_FAILED=1
IOS_RELEASE_NETWORK_DEVICE=fixture
RESULT_DIR="$private"
ios_release_network_require_packet_tunnel_stopped() { printf '{}\n' >"$2"; }
ios_release_network_disconnect_cleanup() { echo launched >"$private/cleanup-launched";return 1; }
release_join_cleanup_ios_network_state
[[ ! -e "$private/cleanup-launched" && ! -e "$RELEASE_JOIN_IOS_QUARANTINE" ]]
# Once a method touched the app, full cleanup remains mandatory.
RELEASE_JOIN_IOS_METHOD_STARTED=1
if release_join_cleanup_ios_network_state; then exit 1;fi
[[ -s "$private/cleanup-launched" && -s "$RELEASE_JOIN_IOS_QUARANTINE" ]]
# Standalone production restore must still execute full cleanup even if this
# shell has not run a test method.
rm "$private/cleanup-launched"
RELEASE_JOIN_IOS_METHOD_STARTED=0
RELEASE_JOIN_IOS_STARTUP_FAILED=0
if release_join_cleanup_ios_network_state; then exit 1;fi
[[ -s "$private/cleanup-launched" ]]
# Simulator mode must never dispatch adb or physical-device checks or repeat
# the full build/test kit before the simulator's own build.
sim_body="$(sed -n '/^  simulator|sim)/,/^    ;;/p' "$ROOT/scripts/mobile-test-kit.sh")"
[[ "$sim_body" != *run_fast* && "$sim_body" != *mobile-android-smoke* ]]
printf 'iOS unattended release harness passed\n'
