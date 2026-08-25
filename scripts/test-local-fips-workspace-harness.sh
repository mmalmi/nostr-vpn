#!/usr/bin/env bash
set -euo pipefail

# This harness creates and validates its own isolated FIPS session. A release
# gate may already have an exact session configured for the real checkout, and
# those credentials must not be applied to the temporary fixture below.
unset NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED
unset NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256
unset NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256
unset NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256
unset NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD
unset NVPN_LOCAL_FIPS_SESSION_FIPS_TREE
unset NVPN_LOCAL_FIPS_PREPARED
unset NVPN_LOCAL_FIPS_ROOT
unset NVPN_LOCAL_FIPS_LOCK_DIR
unset NVPN_LOCAL_FIPS_LOCK_TOKEN
unset NVPN_LOCAL_FIPS_LOCK_SNAPSHOT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/scripts/local-fips-workspace.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-local-fips-harness.XXXXXX")"
APP_ROOT="$TMP_ROOT/app"
FIPS_ROOT="$TMP_ROOT/fips"
LOCK_ROOT="$TMP_ROOT/locks"
ACTIVE="$TMP_ROOT/active"
READY="$TMP_ROOT/stale-ready"
releasing_pid=""
new_owner_pid=""

cleanup() {
  local status="$?" pid
  trap - EXIT INT TERM
  for pid in "$releasing_pid" "$new_owner_pid"; do
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$TMP_ROOT"
  exit "$status"
}
trap cleanup EXIT INT TERM

mkdir -p "$APP_ROOT" "$LOCK_ROOT"
for crate in fips-core fips-endpoint fips-identity; do
  mkdir -p "$FIPS_ROOT/crates/$crate"
  printf '[package]\nname = "nvpn-%s"\nversion = "0.0.0"\n' "$crate" \
    >"$FIPS_ROOT/crates/$crate/Cargo.toml"
done
git -C "$FIPS_ROOT" init -q
git -C "$FIPS_ROOT" add .
git -C "$FIPS_ROOT" \
  -c user.name=Harness -c user.email=harness.invalid commit -qm fixture
printf '[workspace]\nmembers = []\n' >"$APP_ROOT/Cargo.toml"
printf '# original lock\n' >"$APP_ROOT/Cargo.lock"
cp "$APP_ROOT/Cargo.toml" "$TMP_ROOT/Cargo.toml.expected"
cp "$APP_ROOT/Cargo.lock" "$TMP_ROOT/Cargo.lock.expected"

run_worker() {
  local name="$1" dwell="$2"
  env \
    LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
    LOCK_ROOT="$LOCK_ROOT" ACTIVE="$ACTIVE" NAME="$name" DWELL="$dwell" \
    bash -c '
      set -euo pipefail
      source "$LIB"
      export NVPN_FIPS_REPO_PATH="$FIPS_ROOT"
      export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
      nvpn_prepare_local_fips_workspace "$APP_ROOT"
      [[ "$(command -v cargo)" == "$NVPN_LOCAL_FIPS_LOCK_DIR/cargo-wrapper/cargo" ]]
      cmp -s "$APP_ROOT/Cargo.lock" "$APP_ROOT/../Cargo.lock.expected"
      mkdir "$ACTIVE"
      printf "%s\n" "$NAME" >"$APP_ROOT/Cargo.lock"
      sleep "$DWELL"
      rmdir "$ACTIVE"
    '
}

run_worker first 0.3 &
first_pid=$!
sleep 0.05
run_worker second 0.1 &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
cmp -s "$APP_ROOT/Cargo.toml" "$TMP_ROOT/Cargo.toml.expected"
cmp -s "$APP_ROOT/Cargo.lock" "$TMP_ROOT/Cargo.lock.expected"
[[ -z "$(find "$LOCK_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]

RELEASE_READY="$TMP_ROOT/release-ready"
RELEASE_CONTINUE="$TMP_ROOT/release-continue"
RELEASE_DONE="$TMP_ROOT/release-done"
NEW_OWNER_READY="$TMP_ROOT/new-owner-ready"
env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" LOCK_ROOT="$LOCK_ROOT" \
  RELEASE_READY="$RELEASE_READY" RELEASE_CONTINUE="$RELEASE_CONTINUE" \
  RELEASE_DONE="$RELEASE_DONE" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_acquire_local_fips_lock "$APP_ROOT"
    NVPN_LOCAL_FIPS_ROOT="$APP_ROOT"
    owned_lock="$NVPN_LOCAL_FIPS_LOCK_DIR"
    printf "# retiring owner\n" >"$APP_ROOT/Cargo.lock"
    rm() {
      if [[ "$1" == "-rf" ]]; then
        case "${2:-}" in
          "$owned_lock")
            command rm -rf "$owned_lock"
            : >"$RELEASE_READY"
            while [[ ! -f "$RELEASE_CONTINUE" ]]; do sleep 0.01; done
            command rm -rf "$owned_lock"
            return
            ;;
          "$owned_lock".release.*)
            : >"$RELEASE_READY"
            while [[ ! -f "$RELEASE_CONTINUE" ]]; do sleep 0.01; done
            command rm -rf "${2}"
            return
            ;;
        esac
      fi
      command rm "$@"
    }
    nvpn_restore_local_fips_workspace
    : >"$RELEASE_DONE"
  ' &
releasing_pid=$!
for _ in $(seq 1 500); do
  [[ -f "$RELEASE_READY" ]] && break
  sleep 0.01
done
[[ -f "$RELEASE_READY" ]]

env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" LOCK_ROOT="$LOCK_ROOT" \
  RELEASE_DONE="$RELEASE_DONE" NEW_OWNER_READY="$NEW_OWNER_READY" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_acquire_local_fips_lock "$APP_ROOT"
    NVPN_LOCAL_FIPS_ROOT="$APP_ROOT"
    : >"$NEW_OWNER_READY"
    while [[ ! -f "$RELEASE_DONE" ]]; do sleep 0.01; done
    [[ -d "$NVPN_LOCAL_FIPS_LOCK_DIR" ]]
    [[ "$(<"$NVPN_LOCAL_FIPS_LOCK_DIR/token")" == "$NVPN_LOCAL_FIPS_LOCK_TOKEN" ]]
    nvpn_restore_local_fips_workspace
  ' &
new_owner_pid=$!
for _ in $(seq 1 500); do
  [[ -f "$NEW_OWNER_READY" ]] && break
  sleep 0.01
done
[[ -f "$NEW_OWNER_READY" ]]
: >"$RELEASE_CONTINUE"
wait_status=0
wait "$releasing_pid" || wait_status=$?
releasing_pid=""
[[ "$wait_status" -eq 0 ]] || exit "$wait_status"
wait "$new_owner_pid" || wait_status=$?
new_owner_pid=""
[[ "$wait_status" -eq 0 ]] || exit "$wait_status"
cmp -s "$APP_ROOT/Cargo.lock" "$TMP_ROOT/Cargo.lock.expected"
[[ -z "$(find "$LOCK_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]

env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_FIPS_REPO_PATH="$FIPS_ROOT"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_prepare_local_fips_workspace "$APP_ROOT"
    rm -f "$APP_ROOT/Cargo.lock"
  ' >"$TMP_ROOT/deletion.log"
grep -Fq 'restored Cargo.lock after local-FIPS cargo run' "$TMP_ROOT/deletion.log"
cmp -s "$APP_ROOT/Cargo.lock" "$TMP_ROOT/Cargo.lock.expected"
[[ -z "$(find "$LOCK_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]

env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" READY="$READY" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_FIPS_REPO_PATH="$FIPS_ROOT"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_prepare_local_fips_workspace "$APP_ROOT"
    printf "# abandoned lock\n" >"$APP_ROOT/Cargo.lock"
    : >"$READY"
    while :; do sleep 1; done
  ' &
stale_pid=$!
for _ in $(seq 1 100); do
  [[ -f "$READY" ]] && break
  sleep 0.02
done
[[ -f "$READY" ]]
kill -KILL "$stale_pid"
wait "$stale_pid" 2>/dev/null || true
run_worker recovered 0.01 >"$TMP_ROOT/recovery.log"
grep -Fq 'recovered stale local-FIPS workspace owner' "$TMP_ROOT/recovery.log"
cmp -s "$APP_ROOT/Cargo.lock" "$TMP_ROOT/Cargo.lock.expected"
[[ -z "$(find "$LOCK_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]

env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_acquire_local_fips_lock "$APP_ROOT"
    NVPN_LOCAL_FIPS_ROOT="$APP_ROOT"
    owned_lock="$NVPN_LOCAL_FIPS_LOCK_DIR"
    printf "%s\n" "different-owner" >"$owned_lock/token"
    if nvpn_restore_local_fips_workspace; then
      echo "local-FIPS cleanup accepted a changed ownership token" >&2
      exit 1
    fi
    [[ -d "$owned_lock" ]]
    command rm -rf "$owned_lock"
  '

env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_acquire_local_fips_lock "$APP_ROOT"
    NVPN_LOCAL_FIPS_ROOT="$APP_ROOT"
    owned_lock="$NVPN_LOCAL_FIPS_LOCK_DIR"
    rm() {
      if [[ "$1" == "-rf" ]]; then
        case "${2:-}" in
          "$owned_lock".release.*) return 73 ;;
        esac
      fi
      command rm "$@"
    }
    if nvpn_restore_local_fips_workspace; then
      echo "local-FIPS cleanup ignored lock removal failure" >&2
      exit 1
    fi
    [[ ! -e "$owned_lock" ]]
    retired_lock="$(
      find "$LOCK_ROOT" -mindepth 1 -maxdepth 1 -type d \
        -name "$(basename "$owned_lock").release.*" -print -quit
    )"
    [[ -n "$retired_lock" && -d "$retired_lock" ]]
    [[ -z "${NVPN_LOCAL_FIPS_LOCK_DIR:-}" ]]
    unset -f rm
    command rm -rf "$retired_lock"
  '

env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_acquire_local_fips_lock "$APP_ROOT"
    NVPN_LOCAL_FIPS_ROOT="$APP_ROOT"
    owned_lock="$NVPN_LOCAL_FIPS_LOCK_DIR"
    command rm -rf "$owned_lock"
    if nvpn_restore_local_fips_workspace; then
      echo "local-FIPS cleanup accepted a missing owned lock" >&2
      exit 1
    fi
  '

env \
  LIB="$LIB" FIPS_ROOT="$FIPS_ROOT" LOCK_ROOT="$LOCK_ROOT" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    NVPN_LOCAL_FIPS_LOCK_DIR="$LOCK_ROOT/wrapper-setup-failure"
    original_path="$PATH"
    mkdir() {
      return 71
    }
    if nvpn_install_local_fips_cargo_wrapper "$FIPS_ROOT"; then
      echo "local-FIPS wrapper setup ignored directory creation failure" >&2
      exit 1
    fi
    [[ "$PATH" == "$original_path" ]]
    [[ ! -e "$NVPN_LOCAL_FIPS_LOCK_DIR" ]]
  '

env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_FIPS_REPO_PATH="$FIPS_ROOT"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_install_local_fips_cargo_wrapper() {
      return 72
    }
    if nvpn_prepare_local_fips_workspace "$APP_ROOT"; then
      echo "local-FIPS prepare ignored wrapper setup failure" >&2
      exit 1
    fi
    [[ -z "${NVPN_LOCAL_FIPS_PREPARED:-}" ]]
    [[ -z "$(trap -p EXIT)" ]]
    [[ -z "$(find "$LOCK_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]
  '

env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" MARKER="$TMP_ROOT/acquire-failure-installed" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_FIPS_REPO_PATH="$FIPS_ROOT"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_local_fips_file_sha256() {
      return 74
    }
    nvpn_install_local_fips_cargo_wrapper() {
      : >"$MARKER"
    }
    if nvpn_prepare_local_fips_workspace "$APP_ROOT"; then
      echo "local-FIPS prepare ignored lock acquisition failure" >&2
      exit 1
    fi
    [[ ! -e "$MARKER" ]]
    [[ -z "${NVPN_LOCAL_FIPS_PREPARED:-}" ]]
    [[ -z "$(trap -p EXIT)" ]]
    [[ -z "$(find "$LOCK_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]
  '

real_cargo="$(command -v cargo)"
manifest_sha="$(shasum -a 256 "$APP_ROOT/Cargo.toml" | awk '{print $1}')"
lock_sha="$(shasum -a 256 "$APP_ROOT/Cargo.lock" | awk '{print $1}')"
fips_path_sha="$(
  printf '%s' "$(cd "$FIPS_ROOT" && pwd -P)" | shasum -a 256 | awk '{print $1}'
)"
fips_head="$(git -C "$FIPS_ROOT" rev-parse HEAD)"
fips_tree="$(git -C "$FIPS_ROOT" rev-parse 'HEAD^{tree}')"
env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" REAL_CARGO="$real_cargo" \
  NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED=1 \
  NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256="$manifest_sha" \
  NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256="$lock_sha" \
  NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256="$fips_path_sha" \
  NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD="$fips_head" \
  NVPN_LOCAL_FIPS_SESSION_FIPS_TREE="$fips_tree" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_FIPS_REPO_PATH="$FIPS_ROOT"
    export NVPN_LOCAL_FIPS_LOCK_ROOT="$LOCK_ROOT"
    nvpn_prepare_local_fips_workspace "$APP_ROOT"
    [[ "$(command -v cargo)" == "$REAL_CARGO" ]]
  '
if env \
  LIB="$LIB" APP_ROOT="$APP_ROOT" FIPS_ROOT="$FIPS_ROOT" \
  LOCK_ROOT="$LOCK_ROOT" \
  NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED=1 \
  NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256="$manifest_sha" \
  NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256="$lock_sha" \
  NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256="$fips_path_sha" \
  NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD=0000000000000000000000000000000000000000 \
  NVPN_LOCAL_FIPS_SESSION_FIPS_TREE="$fips_tree" \
  bash -c '
    set -euo pipefail
    source "$LIB"
    export NVPN_FIPS_REPO_PATH="$FIPS_ROOT"
    nvpn_prepare_local_fips_workspace "$APP_ROOT"
  ' >/dev/null 2>&1
then
  echo "preconfigured local-FIPS session accepted the wrong revision" >&2
  exit 1
fi
cmp -s "$APP_ROOT/Cargo.toml" "$TMP_ROOT/Cargo.toml.expected"
cmp -s "$APP_ROOT/Cargo.lock" "$TMP_ROOT/Cargo.lock.expected"
[[ -z "$(find "$LOCK_ROOT" -mindepth 1 -maxdepth 1 -print -quit)" ]]

echo "local FIPS workspace locking harness passed"
