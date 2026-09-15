#!/usr/bin/env bash
# The public musl builder must not consult an unrelated desktop credential
# helper. Custom images still use the caller's normal Docker configuration.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="$ROOT/scripts/build-nvpn-linux-musl"
TARGET=x86_64-unknown-linux-musl
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-musl-docker-config.XXXXXX")"

fail() {
  echo "Linux musl Docker config harness failed: $*" >&2
  exit 1
}

cleanup() {
  local status="$?"
  trap - EXIT
  find "$TMP_ROOT" -xdev -depth -mindepth 1 -delete
  rmdir "$TMP_ROOT"
  exit "$status"
}
trap cleanup EXIT

mkdir -p "$TMP_ROOT/bin" "$TMP_ROOT/home/.docker" "$TMP_ROOT/state"
cat >"$TMP_ROOT/home/.docker/config.json" <<'JSON'
{"credsStore":"desktop"}
JSON
cat >"$TMP_ROOT/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

config_dir=""
if [[ ${1:-} == --config ]]; then
  config_dir="${2:-}"
  shift 2
fi
if [[ ${1:-} == image && ${2:-} == inspect ]]; then
  case "${!#}" in
    messense/rust-musl-cross:*)
      [[ -n "$config_dir" ]] || exit 89
      printf 'sha256:1111111111111111111111111111111111111111111111111111111111111111 linux/amd64\n'
      ;;
    registry.invalid/*)
      [[ -z "$config_dir" ]] || exit 91
      printf 'sha256:2222222222222222222222222222222222222222222222222222222222222222 linux/arm64\n'
      ;;
    *) exit 92 ;;
  esac
  exit 0
fi
[[ ${1:-} == run ]] || exit 97

output_mount=""
cache_volume=""
bound_target=0
image=""
platform=""
previous=""
for argument in "$@"; do
  if [[ "$previous" == --platform ]]; then
    platform="$argument"
  fi
  if [[ "$previous" == -v && "$argument" == *:/home/rust/src/target ]]; then
    bound_target=1
  fi
  if [[ "$previous" == -v && "$argument" == *:/home/rust/output ]]; then
    output_mount="${argument%:/home/rust/output}"
  fi
  if [[ "$previous" == -v && "$argument" == *:/tmp/nvpn-cache ]]; then
    cache_volume="${argument%:/tmp/nvpn-cache}"
  fi
  case "$argument" in
    sha256:1111*) image=messense/rust-musl-cross:public ;;
    sha256:2222*) image=registry.invalid/private-musl:test ;;
  esac
  previous="$argument"
done

case "$image" in
  messense/rust-musl-cross:*)
    if [[ -z "$config_dir" ]]; then
      : >"$NVPN_TEST_STATE_DIR/desktop-helper-used"
      exit 89
    fi
    [[ -d "$config_dir" && ! -e "$config_dir/config.json" ]] || exit 90
    printf '%s\n' "$config_dir" >"$NVPN_TEST_STATE_DIR/public-config"
    [[ "$platform" == linux/amd64 ]] || exit 98
    ;;
  registry.invalid/*)
    [[ -z "$config_dir" ]] || exit 91
    [[ -z "$platform" ]] || exit 99
    : >"$NVPN_TEST_STATE_DIR/custom-used-normal-config"
    ;;
  *)
    exit 92
    ;;
esac

[[ "$bound_target" == 0 ]] || exit 93
[[ "$cache_volume" == nvpn-musl-* && "$cache_volume" != */* ]] || exit 94
# The first container initializes ownership of the persistent native volume.
[[ -n "$output_mount" ]] || exit 0
printf '%s\n' "$cache_volume" >>"$NVPN_TEST_STATE_DIR/cache-volumes"
cat >"$NVPN_TEST_STATE_DIR/container-script"
grep -Fq 'export CARGO_TARGET_DIR=/tmp/nvpn-cache/target' \
  "$NVPN_TEST_STATE_DIR/container-script" || exit 95
grep -Fq '"$CARGO_TARGET_DIR/$TARGET/release/nvpn"' \
  "$NVPN_TEST_STATE_DIR/container-script" || exit 96
grep -Fq '"$OUTPUT_ROOT/$TARGET/release/nvpn"' \
  "$NVPN_TEST_STATE_DIR/container-script" || exit 97
grep -Fq 'exec 9>/tmp/nvpn-cache/build.lock' \
  "$NVPN_TEST_STATE_DIR/container-script" || exit 98
grep -Fxq 'flock 9' "$NVPN_TEST_STATE_DIR/container-script" || exit 99
mkdir -p "$output_mount/$NVPN_TEST_TARGET/release"
printf '#!/bin/sh\nexit 0\n' >"$output_mount/$NVPN_TEST_TARGET/release/nvpn"
chmod +x "$output_mount/$NVPN_TEST_TARGET/release/nvpn"
SH
chmod +x "$TMP_ROOT/bin/docker"

run_builder() {
  local name="$1"
  shift
  mkdir -p "$TMP_ROOT/$name-build" "$TMP_ROOT/$name-target"
  env \
    PATH="$TMP_ROOT/bin:$PATH" \
    HOME="$TMP_ROOT/home" \
    NVPN_TEST_STATE_DIR="$TMP_ROOT/state" \
    NVPN_TEST_TARGET="$TARGET" \
    NVPN_LINUX_MUSL_KEEP_WORK=1 \
    NVPN_LINUX_MUSL_BUILD_ROOT="$TMP_ROOT/$name-build" \
    NVPN_LINUX_MUSL_TARGET_DIR="$TMP_ROOT/$name-target" \
    "$@" \
    "$BUILDER" "$TARGET"
}

public_binary="$(run_builder public)"
[[ -x "$public_binary" ]] || fail "public-image build did not emit its binary"
[[ ! -e "$TMP_ROOT/state/desktop-helper-used" ]] \
  || fail "public image consulted the desktop credential helper"
public_config="$(cat "$TMP_ROOT/state/public-config")"
[[ "$public_config" == "$TMP_ROOT/public-build/"*/.docker-public ]] \
  || fail "public image did not use a per-run Docker config"
[[ -z "$(find "$public_config" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
  || fail "public per-run Docker config was not empty"

repeat_binary="$(run_builder repeat)"
[[ -x "$repeat_binary" ]] || fail "repeated build did not emit its binary"

custom_binary="$(
  run_builder custom NVPN_LINUX_MUSL_IMAGE=registry.invalid/private-musl:test
)"
[[ -x "$custom_binary" ]] || fail "custom-image build did not emit its binary"
[[ -e "$TMP_ROOT/state/custom-used-normal-config" ]] \
  || fail "custom image did not preserve the caller's Docker configuration"

cache_volumes=()
while IFS= read -r line; do cache_volumes+=("$line"); done \
  <"$TMP_ROOT/state/cache-volumes"
[[ "${#cache_volumes[@]}" == 3 \
  && "${cache_volumes[0]}" == "${cache_volumes[1]}" \
  && "${cache_volumes[0]}" != "${cache_volumes[2]}" ]] \
  || fail "cache must survive repeated workspaces and isolate builder images"

echo "Linux musl Docker config and cache harness passed"
