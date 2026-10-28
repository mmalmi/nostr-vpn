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
printf '%s\n' "$*" >>"$NVPN_TEST_STATE_DIR/docker-calls"
if [[ ${1:-} == --config ]]; then
  config_dir="${2:-}"
  shift 2
fi
if [[ ${1:-} == image && ${2:-} == inspect ]]; then
  [[ ${NVPN_TEST_IMAGE_MISSING:-0} != 1 ]] || exit 1
  case "${!#}" in
    messense/rust-musl-cross:*@sha256:*)
      [[ -n "$config_dir" ]] || exit 89
      printf 'sha256:1111111111111111111111111111111111111111111111111111111111111111 linux/amd64\n'
      ;;
    registry.invalid/*@sha256:*|sha256:2222*)
      [[ -z "$config_dir" ]] || exit 91
      printf '%s linux/arm64\n' "${NVPN_TEST_IMAGE_ID:-sha256:2222222222222222222222222222222222222222222222222222222222222222}"
      ;;
    *) exit 92 ;;
  esac
  exit 0
fi
[[ ${1:-} == run ]] || exit 97

output_mount=""
source_mount=""
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
  if [[ "$previous" == -v && "$argument" == *:/home/rust/src ]]; then
    source_mount="${argument%:/home/rust/src}"
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
if [[ ${NVPN_TEST_LOCAL_FIPS:-0} == 1 ]]; then
  test -d "$source_mount/.fips-patch"
  specs="$(python3 "$source_mount/scripts/verify-cargo-path-patch-lock.py" \
    --manifest-specs "$source_mount/.fips-patch")"
  # Compare all lock bytes against the committed input, not just package names.
  python3 "$source_mount/scripts/verify-cargo-path-patch-lock.py" \
    --validate "$NVPN_TEST_COMMITTED_LOCK" "$source_mount/Cargo.lock" $specs \
    >"$NVPN_TEST_STATE_DIR/local-fips-lock-sha256"
fi
grep -Fq 'export CARGO_TARGET_DIR=/tmp/nvpn-cache/target' \
  "$NVPN_TEST_STATE_DIR/container-script" || exit 95
grep -Fq '"$CARGO_TARGET_DIR/$TARGET/release/nvpn"' \
  "$NVPN_TEST_STATE_DIR/container-script" || exit 96
grep -Fq '"$OUTPUT_ROOT/$TARGET/release/nvpn"' \
  "$NVPN_TEST_STATE_DIR/container-script" || exit 97
grep -Fq 'exec 9>/tmp/nvpn-cache/build.lock' \
  "$NVPN_TEST_STATE_DIR/container-script" || exit 98
grep -Fxq 'flock 9' "$NVPN_TEST_STATE_DIR/container-script" || exit 99
grep -Fq 'fetch --locked --target' "$NVPN_TEST_STATE_DIR/container-script" || exit 100
grep -Fq 'build --frozen' "$NVPN_TEST_STATE_DIR/container-script" || exit 101
! grep -Fq ' update -p ' "$NVPN_TEST_STATE_DIR/container-script" || exit 102
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
  run_builder custom NVPN_LINUX_MUSL_IMAGE=registry.invalid/private-musl:test@sha256:3333333333333333333333333333333333333333333333333333333333333333
)"
[[ -x "$custom_binary" ]] || fail "custom-image build did not emit its binary"
[[ -e "$TMP_ROOT/state/custom-used-normal-config" ]] \
  || fail "custom image did not preserve the caller's Docker configuration"

local_binary="$(
  run_builder local NVPN_LINUX_MUSL_IMAGE=sha256:2222222222222222222222222222222222222222222222222222222222222222
)"
[[ -x "$local_binary" ]] || fail "exact local builder did not emit its binary"

calls_before="$(wc -l <"$TMP_ROOT/state/docker-calls")"
if run_builder mutable NVPN_LINUX_MUSL_IMAGE=registry.invalid/private-musl:test \
  >"$TMP_ROOT/mutable.log" 2>&1; then
  fail "mutable custom image was accepted"
fi
[[ "$(wc -l <"$TMP_ROOT/state/docker-calls")" == "$calls_before" ]] \
  || fail "mutable image rejection contacted Docker"
if run_builder mismatch \
  NVPN_LINUX_MUSL_IMAGE=sha256:2222222222222222222222222222222222222222222222222222222222222222 \
  NVPN_TEST_IMAGE_ID=sha256:4444444444444444444444444444444444444444444444444444444444444444 \
  >"$TMP_ROOT/mismatch.log" 2>&1; then
  fail "different local builder image was accepted"
fi
if run_builder missing \
  NVPN_LINUX_MUSL_IMAGE=sha256:2222222222222222222222222222222222222222222222222222222222222222 \
  NVPN_TEST_IMAGE_MISSING=1 >"$TMP_ROOT/missing.log" 2>&1; then
  fail "missing local builder was accepted"
fi
! grep -E '^pull | pull ' "$TMP_ROOT/state/docker-calls" >/dev/null \
  || fail "missing local image caused a pull fallback"

cache_volumes=()
while IFS= read -r line; do cache_volumes+=("$line"); done \
  <"$TMP_ROOT/state/cache-volumes"
[[ "${#cache_volumes[@]}" == 4 \
  && "${cache_volumes[0]}" == "${cache_volumes[1]}" \
  && "${cache_volumes[0]}" != "${cache_volumes[2]}" \
  && "${cache_volumes[2]}" == "${cache_volumes[3]}" ]] \
  || fail "cache must survive repeated workspaces and isolate builder images"

# A local FIPS checkout must use the exact published versions without asking
# Cargo to resolve a new lock. Construct only the manifests this path reads.
python3 - "$ROOT" "$TMP_ROOT/fips" <<'PY_FIXTURE'
import importlib.util, pathlib, sys
root, fixture = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("patch_lock", root / "scripts/verify-cargo-path-patch-lock.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
versions = module.lock_specs((root / "Cargo.lock").read_bytes())
for name, relative in module.patch_crates(versions["nvpn-webrtc"]).items():
    path = fixture / relative / "Cargo.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = f'[package]\nname = "{name}"\nversion = "{versions[name]}"\n'
    if name == "nvpn-webrtc" and "nvpn-dtls" in versions:
        text += f'\n[dependencies.dtls]\npackage = "nvpn-dtls"\npath = "../dtls"\nversion = "={versions["nvpn-dtls"]}"\n'
    path.write_text(text)
PY_FIXTURE
git -C "$TMP_ROOT/fips" init -q
git -C "$TMP_ROOT/fips" add .
git -C "$TMP_ROOT/fips" -c user.name=Test -c user.email=test@example.invalid \
  commit -qm 'Exact local FIPS fixture'
patched_binary="$(run_builder patched NVPN_FIPS_REPO_PATH="$TMP_ROOT/fips" \
  NVPN_TEST_LOCAL_FIPS=1 NVPN_TEST_COMMITTED_LOCK="$ROOT/Cargo.lock")"
[[ -x "$patched_binary" && -s "$TMP_ROOT/state/local-fips-lock-sha256" ]] \
  || fail "local FIPS build did not preserve the exact dependency lock"

python3 - "$TMP_ROOT/fips/crates/fips-core/Cargo.toml" <<'PY_MISMATCH'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1])
p.write_text(re.sub(r'^version = .*$', 'version = "99.0.0"', p.read_text(), flags=re.M))
PY_MISMATCH
git -C "$TMP_ROOT/fips" add .
git -C "$TMP_ROOT/fips" -c user.name=Test -c user.email=test@example.invalid \
  commit -qm 'Mismatching local FIPS fixture'
calls_before="$(wc -l <"$TMP_ROOT/state/docker-calls")"
if run_builder wrong-fips NVPN_FIPS_REPO_PATH="$TMP_ROOT/fips" \
  >"$TMP_ROOT/wrong-fips.log" 2>&1; then
  fail "local FIPS version mismatch was accepted"
fi
[[ "$(wc -l <"$TMP_ROOT/state/docker-calls")" == "$calls_before" ]] \
  || fail "local FIPS version mismatch started Docker"
grep -q 'expected 99.0.0' "$TMP_ROOT/wrong-fips.log" \
  || fail "version mismatch did not fail at exact lock validation"

echo "Linux musl Docker config, immutable inputs and cache harness passed (9 cases)"
