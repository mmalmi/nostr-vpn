#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh"
REMOTE="$ROOT/scripts/macos-release-mobile-join-remote.sh"
HELPER="$ROOT/scripts/lib-macos-release-app-ownership.sh"
trap 'echo "macOS app ownership harness failed at line $LINENO" >&2' ERR

bash -n "$HOST" "$REMOTE" "$HELPER"
python3 - "$HOST" "$REMOTE" "$HELPER" <<'PY'
import pathlib
import sys

host = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
remote = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
helper = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")

for required in (
    "remote_app_ownership_armed=0",
    'if [[ "$remote_app_ownership_armed" -eq 1 ]]',
    "remote_app_ownership_armed=1",
    "macos_release_stop_owned_child",
):
    if required not in host:
        raise SystemExit(f"host importer lacks cleanup ownership guard: {required}")
if host.index("remote_app_ownership_armed=1") > host.index(
    'remote create-admin "ReleaseDesktopAdmin"'
):
    raise SystemExit("host importer arms cleanup after its first app launch")
cleanup = host.split("cleanup() {", 1)[1].split("trap cleanup EXIT", 1)[0]
if "remote cleanup" not in cleanup or "remote_app_ownership_armed" not in cleanup:
    raise SystemExit("host cleanup is not conditional on remote app ownership")

for required in (
    'NVPN_MACOS_RELEASE_MOBILE_DIRECTIONS:-all',
    'all|pixel)',
    'if [[ "$MACOS_MOBILE_DIRECTIONS" == "all" ]]; then',
    "release_join_validate_reused_android_only",
    '"selectedDirections": selected',
):
    if required not in host:
        raise SystemExit(f"macOS/mobile direction selector lacks {required}")
if '${android_install_validation[@]+"${android_install_validation[@]}"}' not in host:
    raise SystemExit("macOS/Pixel validator is not safe with an empty optional-argument array")
for required in (
    'local quarantine="${TEST_CONFIG_DIR}.quarantine.',
    'mv "$TEST_CONFIG_DIR" "$quarantine"',
    "could not quarantine privileged macOS Release join test profile",
):
    if required not in remote:
        raise SystemExit(f"privileged profile cleanup lacks recoverable quarantine: {required}")

directions = (
    ("macOS admin -> physical Android joiner.", "macos-admin-pixel-joiner"),
    ("Physical Android admin -> macOS joiner.", "pixel-admin-macos-joiner"),
    ("macOS admin -> physical iPhone joiner.", "macos-admin-iphone-joiner"),
    ("Physical iPhone admin -> macOS joiner.", "iphone-admin-macos-joiner"),
)
for index, (comment, label) in enumerate(directions):
    start = host.index(f"# {comment}")
    end = (
        host.index(f"# {directions[index + 1][0]}", start)
        if index + 1 < len(directions)
        else host.index("if ((macos_admin_android_status", start)
    )
    phase = host[start:end]
    for required in (
        "trap macos_mobile_direction_cleanup EXIT",
        "prepare_macos_mobile_direction",
        f"finish_macos_mobile_direction {label}",
    ):
        if required not in phase:
            raise SystemExit(f"{label} lacks isolated lifecycle step: {required}")
if host.count('prepare_macos_mobile_direction "$') != 4:
    raise SystemExit("each macOS/mobile direction must start one fresh profile")
if host.count("finish_macos_mobile_direction ") != 4:
    raise SystemExit("each macOS/mobile direction must clean its profile")
if "recover_macos_android_direction" in host:
    raise SystemExit("macOS/mobile directions still share success-path profile state")
prepare = host.split("prepare_macos_mobile_direction() {", 1)[1].split("\n}", 1)[0]
if prepare.index("remote reset-profile") > prepare.index("remote service-preflight"):
    raise SystemExit("a macOS/mobile direction starts before clearing prior profile state")
direction_cleanup = host.split("macos_mobile_direction_cleanup() {", 1)[1].split(
    "\n}\n\nprepare_macos_mobile_direction", 1
)[0]
for required in (
    '"$RELEASE_JOIN_IOS_TEST_PID" "$ios_test_pid_owner"',
    'macos_release_stop_owned_child "$remote_pid" "$remote_pid_owner"',
):
    if required not in direction_cleanup:
        raise SystemExit(f"direction cleanup leaks a local runner: {required}")
if host.count('macos_mobile_direction_child_owner "$remote_pid"') != 4:
    raise SystemExit("remote direction children are not all bound to their exact parent")
if host.count('macos_mobile_direction_child_owner "$RELEASE_JOIN_IOS_TEST_PID"') != 2:
    raise SystemExit("iOS direction runners are not bound to their exact parent")
for status in (
    "macos_admin_android_status", "android_admin_macos_status",
    "macos_admin_ios_status", "ios_admin_macos_status",
):
    aggregate = host.split(
        'echo "One or more macOS/mobile manual-join directions failed"', 1
    )[0].rsplit("if ((", 1)[1]
    if status not in aggregate:
        raise SystemExit(f"aggregate gate result omits {status}")

for required in (
    "lib-macos-release-app-ownership.sh",
    "macos_release_app_acquire",
    "macos_release_app_restore",
    "MACOS_RELEASE_APP_STATE_DIR",
    "MACOS_RELEASE_APP_INSTALLED_EXE",
    "MACOS_RELEASE_APP_GATE_EXE",
):
    if required not in remote:
        raise SystemExit(f"VM importer lacks app ownership contract: {required}")
for required in (
    "trap stop_app EXIT",
    "trap 'exit 129' HUP",
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
):
    if required not in remote:
        raise SystemExit(f"VM importer lacks signal-safe app cleanup: {required}")
if 'pkill -x "Nostr VPN"' in remote or "pkill" in helper:
    raise SystemExit("VM importer still has a broad Nostr VPN process kill")
stage = remote.split("stage() {", 1)[1].split("prepare() {", 1)[0]
if stage.index("macos_release_app_restore") > stage.index('rm -rf "$ARTIFACT_DIR"'):
    raise SystemExit("VM staging deletes ownership before restoring prior state")
launch = remote.split("launch_app() {", 1)[1].split("run_driver() {", 1)[0]
if launch.index("macos_release_app_acquire") > launch.index('"$APP_EXE"'):
    raise SystemExit("VM importer launches before acquiring app ownership")
cleanup_case = remote.split("  cleanup)", 1)[1].split("    ;;", 1)[0]
if "macos_release_app_restore" not in cleanup_case:
    raise SystemExit("VM cleanup does not restore the displaced installed app")
for required in (
    "macos_release_app_acquire",
    "macos_release_app_restore",
    "prior-state",
    "imported.pid",
    "absent",
    "hidden",
    "visible",
):
    if required not in helper:
        raise SystemExit(f"ownership helper lacks {required}")
stop = helper.split("macos_release_app_stop_pid() {", 1)[1].split(
    "\n}\n\nmacos_release_app_acquire()", 1
)[0]
for required in (
    "kill -TERM",
    "kill -KILL",
    "gate-owned app process survived TERM and KILL",
):
    if required not in stop:
        raise SystemExit(f"bounded stop helper lacks {required}")
if stop.count("macos_release_app_poll_pid_gone") < 2 or "wait " in stop:
    raise SystemExit("bounded stop helper does not poll twice without blocking wait")
if "macos_release_stop_owned_child" not in helper:
    raise SystemExit("host remote child has no shared bounded stop helper")
owned_child = helper.split("macos_release_stop_owned_child() {", 1)[1].split(
    "\n}\n\nmacos_release_app_stop_pid()", 1
)[0]
if 'owner_pid="${2:-$$}"' not in owned_child:
    raise SystemExit("bounded child cleanup cannot bind a direction subshell owner")
PY

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-app-owner.XXXXXX")"
fixture_name="NvOwn$$"
cleanup() {
  while IFS= read -r pid; do
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
  done < <(pgrep -x "$fixture_name" 2>/dev/null || true)
  rm -rf "$tmp"
}
trap cleanup EXIT

python3 - "$HOST" "$tmp/host-cleanup.sh" <<'PY'
import pathlib
import sys

host = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
cleanup = host.split("cleanup() {", 1)[1].split(
    "\n}\ntrap cleanup EXIT", 1
)[0]
pathlib.Path(sys.argv[2]).write_text(
    "cleanup() {" + cleanup + "\n}\n",
    encoding="utf-8",
)
PY
bash -s -- "$tmp/host-cleanup.sh" "$tmp" <<'TEST'
set -euo pipefail
cleanup_source="$1"
tmp="$2"
# shellcheck disable=SC1090
source "$cleanup_source"

run_cleanup_case() {
  local primary_status="$1"
  local remote_status="$2"
  remote_pid=""
  remote_app_ownership_armed=1
  remote_harness_install_attempted=0
  PRIVATE_DIR="$tmp/private-$primary_status-$remote_status"
  mkdir -p "$PRIVATE_DIR"
  remote() {
    echo "synthetic remote cleanup failure" >&2
    return "$remote_status"
  }
  set +e
  (exit "$primary_status")
  cleanup
}

assert_cleanup_case() {
  local primary_status="$1" remote_status="$2" expected="$3"
  local output observed
  set +e
  output="$(run_cleanup_case "$primary_status" "$remote_status" 2>&1)"
  observed=$?
  set -e
  [[ "$observed" -eq "$expected" ]] || {
    echo "cleanup status mismatch: primary=$primary_status cleanup=$remote_status observed=$observed expected=$expected" >&2
    return 1
  }
  grep -Fq "macOS VM app restoration failed during release gate cleanup" \
    <<<"$output" || {
      echo "cleanup failure was not reported" >&2
      return 1
    }
}

assert_cleanup_case 0 23 23
assert_cleanup_case 17 23 17
TEST

mkdir -p \
  "$tmp/installed/$fixture_name.app/Contents/MacOS" \
  "$tmp/unknown" \
  "$tmp/stubborn"
installed="$tmp/installed/$fixture_name.app/Contents/MacOS/$fixture_name"
unknown="$tmp/unknown/$fixture_name"
stubborn="$tmp/stubborn/$fixture_name"
fixture_source='#include <signal.h>
#include <unistd.h>
int main(void) {
  signal(SIGTERM, SIG_DFL);
  for (;;) pause();
}'
printf '%s\n' "$fixture_source" \
  | xcrun clang -x c - -o "$installed"
printf '%s\n' "$fixture_source" \
  | xcrun clang -x c - -o "$unknown"
printf '%s\n' '#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  signal(SIGTERM, SIG_IGN);
  int ready = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (ready < 0) return 3;
  close(ready);
  for (;;) pause();
}' | xcrun clang -x c - -o "$stubborn"

bash -s -- \
  "$HELPER" "$installed" "$unknown" "$stubborn" "$fixture_name" "$tmp" <<'TEST'
set -euo pipefail
trap 'echo "ownership fixture failed at line $LINENO" >&2' ERR
helper="$1"
installed="$2"
unknown="$3"
stubborn="$4"
fixture_name="$5"
tmp="$6"

# shellcheck disable=SC1090
source "$helper"

set_artifact() {
  MACOS_RELEASE_APP_STATE_DIR="$1/app-ownership"
  MACOS_RELEASE_APP_GATE_EXE="$1/imported/$fixture_name.app/Contents/MacOS/$fixture_name"
  MACOS_RELEASE_APP_INSTALLED_EXE="$installed"
  MACOS_RELEASE_APP_PROCESS_NAME="$fixture_name"
  APP_PID=""
  mkdir -p "$(dirname "$MACOS_RELEASE_APP_GATE_EXE")"
  printf '%s\n' '#include <signal.h>
#include <unistd.h>
int main(void) {
  signal(SIGTERM, SIG_DFL);
  for (;;) pause();
}' | xcrun clang -x c - -o "$MACOS_RELEASE_APP_GATE_EXE"
}

single_pid() {
  local values
  values="$(pgrep -x "$fixture_name" 2>/dev/null || true)"
  [[ "$(wc -w <<<"$values" | tr -d " ")" == 1 ]]
  printf '%s\n' "$values"
}

stop_fixture() {
  local pid="$1"
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

run_restore_case() {
  local mode="$1" artifact="$2" prior imported restored args
  set_artifact "$artifact"
  if [[ "$mode" == hidden ]]; then
    "$installed" --hidden &
  else
    "$installed" &
  fi
  prior=$!
  disown "$prior"
  sleep 0.1
  [[ "$(single_pid)" == "$prior" ]]

  # This is the original regression: cleanup before ownership must not kill
  # the preexisting installed app.
  macos_release_app_restore
  kill -0 "$prior"
  [[ ! -e "$MACOS_RELEASE_APP_STATE_DIR" ]]

  macos_release_app_acquire
  ! kill -0 "$prior" >/dev/null 2>&1
  [[ "$(<"$MACOS_RELEASE_APP_STATE_DIR/prior-state")" == "$mode" ]]
  "$MACOS_RELEASE_APP_GATE_EXE" &
  imported=$!
  disown "$imported"
  APP_PID="$imported"
  printf '%s\n' "$imported" >"$MACOS_RELEASE_APP_STATE_DIR/imported.pid"

  macos_release_app_restore
  ! kill -0 "$imported" >/dev/null 2>&1
  [[ ! -e "$MACOS_RELEASE_APP_STATE_DIR" ]]
  restored="$(single_pid)"
  [[ "$restored" != "$prior" ]]
  args="$(macos_release_app_process_args "$restored")"
  if [[ "$mode" == hidden ]]; then
    [[ "$args" == "$installed --hidden" ]]
  else
    [[ "$args" == "$installed" ]]
  fi
  APP_PID=""
  stop_fixture "$restored"
}

run_restore_case hidden "$tmp/hidden"
run_restore_case visible "$tmp/visible"

# A same-name process from an unknown executable must be left alone.
set_artifact "$tmp/unknown-case"
"$unknown" &
unknown_pid=$!
disown "$unknown_pid"
sleep 0.1
if macos_release_app_acquire >/dev/null 2>&1; then
  echo "ownership accepted an unknown same-name process" >&2
  exit 1
fi
kill -0 "$unknown_pid"
[[ ! -e "$MACOS_RELEASE_APP_STATE_DIR/acquired" ]]
stop_fixture "$unknown_pid"
APP_PID=""
TEST

# Run both bounded stop paths in a watchdog-protected shell where each
# TERM-ignoring fixture is a real child that must be reaped.
child_pid_file="$tmp/stubborn-child.pid"
kill_events="$tmp/stubborn-kill-events"
worker_log="$tmp/stubborn-worker.log"
bash -s -- "$HELPER" "$stubborn" "$child_pid_file" "$kill_events" \
  >"$worker_log" 2>&1 <<'TEST' &
set -euo pipefail
trap 'echo "bounded stop worker failed at line $LINENO" >&2' ERR
source "$1"
stubborn="$2"
child_pid_file="$3"
kill_events="$4"
child=""
mode=""
kill() {
  if [[ ("${1:-}" == -TERM || "${1:-}" == -KILL) && -n "$mode" ]]; then
    if builtin kill "$@"; then
      printf '%s\t%s\n' "$mode" "${1#-}" >>"$kill_events"
      return 0
    fi
    return 1
  fi
  builtin kill "$@"
}
cleanup_child() {
  [[ -n "$child" ]] || return 0
  kill -KILL "$child" >/dev/null 2>&1 || true
  wait "$child" >/dev/null 2>&1 || true
}
trap cleanup_child EXIT
for mode in exact-app owned-child; do
  ready="$kill_events.$mode.ready"
  "$stubborn" "$ready" &
  child=$!
  printf '%s\n' "$child" >"$child_pid_file"
  for _ in {1..50}; do
    [[ -e "$ready" ]] && break
    sleep 0.02
  done
  [[ -e "$ready" ]]
  if [[ "$mode" == exact-app ]]; then
    macos_release_app_stop_pid "$child" "$stubborn $ready"
  else
    macos_release_stop_owned_child "$child"
  fi
  grep -Fxq "$mode"$'\tTERM' "$kill_events"
  grep -Fxq "$mode"$'\tKILL' "$kill_events"
  ! kill -0 "$child" >/dev/null 2>&1
  [[ -z "$(ps -ww -p "$child" -o stat= 2>/dev/null)" ]]
  child=""
done
trap - EXIT
TEST
worker_pid=$!
timed_out=1
for _ in {1..180}; do
  if ! kill -0 "$worker_pid" >/dev/null 2>&1; then
    timed_out=0
    break
  fi
  sleep 0.1
done
if [[ "$timed_out" -eq 1 ]]; then
  child="$(cat "$child_pid_file" 2>/dev/null || true)"
  [[ -z "$child" ]] || kill -KILL "$child" >/dev/null 2>&1 || true
  kill -KILL "$worker_pid" >/dev/null 2>&1 || true
  wait "$worker_pid" >/dev/null 2>&1 || true
  tail -n 40 "$worker_log" >&2 || true
  echo "bounded stop helper hung on a TERM-ignoring child" >&2
  exit 1
fi
if ! wait "$worker_pid"; then
  tail -n 40 "$worker_log" >&2 || true
  exit 1
fi
# macOS Bash 3 keeps $$ unchanged in subshells. Prove a captured exact parent
# binds the child before bounded cleanup instead of loosening PID ownership.
bash -s -- "$HELPER" <<'TEST'
set -euo pipefail
source "$1"
(
  sleep 60 & child=$!
  owner="$(ps -ww -p "$child" -o ppid= | tr -d '[:space:]')"
  macos_release_stop_owned_child "$child" "$owner"
  ! kill -0 "$child" >/dev/null 2>&1
)
TEST

echo "MACOS_RELEASE_APP_OWNERSHIP_HARNESS_OK"
