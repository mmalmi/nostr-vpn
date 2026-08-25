#!/usr/bin/env bash
# Build/cache exact Ubuntu 24.04 x86_64 artifacts under Mac orchestration.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/mobile_env.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-host-linux-builder-isolation.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-host-linux-native-builder.sh"

load_release_env "$ROOT"
load_mobile_env "$ROOT"
[[ "$(uname -s)" == "Darwin" ]] || {
  echo "Linux release artifacts must be orchestrated by the controlling Mac" >&2
  exit 2
}
BUILDER_MODE="${NVPN_HOST_LINUX_VM_BUILDER_MODE:-}"
case "$BUILDER_MODE" in
  remote-native)
    host_linux_native_builder_configured || {
      echo "remote-native Linux release building requires an explicit host" >&2
      exit 2
    }
    ;;
  local-docker)
    [[ "$(uname -m)" == "x86_64" ]] || {
      echo "local-docker Linux release building requires a native x86_64 Mac" >&2
      exit 2
    }
    [[ -z "${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST:-}" ]] || {
      echo "local-docker Linux release building conflicts with a remote host" >&2
      exit 2
    }
    ;;
  *)
    echo "NVPN_HOST_LINUX_VM_BUILDER_MODE must explicitly select remote-native or local-docker" >&2
    exit 2
    ;;
esac
if [[ "$BUILDER_MODE" == "local-docker" ]]; then
  command -v docker >/dev/null 2>&1 || {
    echo "Local Linux release building requires Docker on the controlling Mac" >&2
    exit 2
  }
fi

APP_GIT_SHA="$(git -C "$ROOT" rev-parse HEAD)"
APP_GIT_TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
APP_GIT_STATUS="$(git -C "$ROOT" status --porcelain --untracked-files=all)"
EXPECTED_APP_GIT_SHA="${NVPN_EXPECTED_APP_GIT_SHA:-$APP_GIT_SHA}"
[[ "$EXPECTED_APP_GIT_SHA" =~ ^[0-9a-f]{40}$ \
  && "$APP_GIT_SHA" == "$EXPECTED_APP_GIT_SHA" ]] || {
  echo "Host Linux VM bundle app commit differs from the exact candidate" >&2
  exit 2
}
[[ -z "$APP_GIT_STATUS" ]] || {
  echo "Host Linux VM bundle refuses a dirty app checkout" >&2
  exit 2
}
if [[ -n "${NVPN_EXPECTED_APP_GIT_TREE:-}" \
  && "$APP_GIT_TREE" != "$NVPN_EXPECTED_APP_GIT_TREE" ]]
then
  echo "Host Linux VM bundle app tree differs from the exact candidate" >&2
  exit 2
fi

candidate_blob_sha256() {
  git -C "$ROOT" cat-file blob "$APP_GIT_SHA:$1" \
    | shasum -a 256 | awk '{print $1}'
}

require_exact_candidate_file() {
  local relative="$1"
  [[ -f "$ROOT/$relative" && ! -L "$ROOT/$relative" \
    && "$(shasum -a 256 "$ROOT/$relative" | awk '{print $1}')" \
      == "$(candidate_blob_sha256 "$relative")" ]] || {
    echo "Host Linux VM bundle candidate file differs from Git: $relative" >&2
    exit 2
  }
}
APP_VERSION="$(
  awk '
    $0 == "[workspace.package]" { package = 1; next }
    package && /^\[/ { exit }
    package && /^version = "/ {
      value = $0
      sub(/^version = "/, "", value)
      sub(/".*$/, "", value)
      print value
      exit
    }
  ' "$ROOT/Cargo.toml"
)"
[[ "$APP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "Host Linux VM bundle could not derive the app version" >&2
  exit 2
}
ROOT_CARGO_LOCK_SHA256="$(shasum -a 256 "$ROOT/Cargo.lock" | awk '{ print $1 }')"
LINUX_CARGO_LOCK_SHA256="$(
  shasum -a 256 "$ROOT/linux/Cargo.lock" | awk '{ print $1 }'
)"
[[ "$ROOT_CARGO_LOCK_SHA256" =~ ^[0-9a-f]{64}$ \
  && "$LINUX_CARGO_LOCK_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "Host Linux VM bundle could not hash the committed Cargo lockfiles" >&2
  exit 2
}

release_join_require_clean_fips
release_join_assert_fips_unchanged
TARGET="x86_64-unknown-linux-gnu"
DOCKER_PLATFORM="linux/amd64"
CONTAINER_BASE="ubuntu:24.04"
RUST_TOOLCHAIN="${NVPN_HOST_LINUX_VM_RUST_TOOLCHAIN:-1.95.0}"
[[ "$RUST_TOOLCHAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "Host Linux VM bundle Rust toolchain must be an exact stable version" >&2
  exit 2
}
CONTAINER_PAYLOAD="$ROOT/scripts/build-host-linux-vm-bundle-in-container.sh"
REMOTE_BUILDER_DRIVER="$ROOT/scripts/host-linux-native-builder-remote.sh"
[[ -x "$CONTAINER_PAYLOAD" && ! -L "$CONTAINER_PAYLOAD" ]] || {
  echo "Host Linux VM bundle container payload is missing" >&2
  exit 2
}
[[ "$BUILDER_MODE" != "remote-native" \
  || ( -x "$REMOTE_BUILDER_DRIVER" && ! -L "$REMOTE_BUILDER_DRIVER" ) ]] || {
  echo "Remote native Linux builder driver is missing" >&2
  exit 2
}
DOCKERFILE_SHA256="$(
  candidate_blob_sha256 Dockerfile.linux-vm-gate
)"
CONTAINER_PAYLOAD_SHA256="$(
  candidate_blob_sha256 scripts/build-host-linux-vm-bundle-in-container.sh
)"
for candidate_file in \
  Dockerfile.linux-vm-gate \
  scripts/build-host-linux-vm-bundle-in-container.sh \
  scripts/host-linux-native-builder-remote.sh
do
  require_exact_candidate_file "$candidate_file"
done
SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct "$APP_GIT_SHA")"
export SOURCE_DATE_EPOCH

CACHE_ROOT="${NVPN_HOST_LINUX_VM_BUNDLE_CACHE_DIR:-${ARTIFACT_ROOT:-$ROOT/artifacts}/host-linux-vm-bundle}"
mkdir -p "$CACHE_ROOT"
CACHE_ROOT="$(cd "$CACHE_ROOT" && pwd)"
HOST_BUILD_LOCK="$CACHE_ROOT/.host-linux-vm-bundle.lock"
CARGO_DEB_VERSION="3.7.0"
MUSL_TARGET="x86_64-unknown-linux-musl"
CACHE_KEY="$APP_GIT_SHA-$RELEASE_JOIN_FIPS_SHA-$TARGET-ubuntu24.04-rust$RUST_TOOLCHAIN-cargo-deb$CARGO_DEB_VERSION-package5-$BUILDER_MODE"
BUNDLE_DIR="$CACHE_ROOT/$CACHE_KEY"
RECEIPT="$BUNDLE_DIR/receipt.json"
BUILD_CACHE_ID="$(
  printf '%s' "$CACHE_ROOT" | shasum -a 256 | awk '{ print $1 }'
)"
TARGET_CACHE_GENERATION="fresh-docker-volume-v5-rust${RUST_TOOLCHAIN//./-}"
TARGET_VOLUME_ID="$(
  printf '%s:%s' "$BUILD_CACHE_ID" "$TARGET_CACHE_GENERATION" \
    | shasum -a 256 | awk '{ print $1 }'
)"
TARGET_VOLUME_NAME="nvpn-linux-target-${TARGET_VOLUME_ID:0:24}"
VERIFIER="$ROOT/scripts/verify-host-linux-vm-bundle.py"
PATCH_LOCK_VERIFIER="$ROOT/scripts/verify-cargo-path-patch-lock.py"
[[ -x "$PATCH_LOCK_VERIFIER" ]] || {
  echo "Host Linux VM bundle exact FIPS lock verifier is missing" >&2
  exit 2
}
require_exact_candidate_file scripts/verify-cargo-path-patch-lock.py
FIPS_PATCH_PACKAGES=()
while IFS= read -r package; do
  FIPS_PATCH_PACKAGES+=("$package")
done < <(
  python3 "$PATCH_LOCK_VERIFIER" \
    --manifest-specs "$NVPN_FIPS_REPO_PATH"
)
[[ "${#FIPS_PATCH_PACKAGES[@]}" == 3 ]] || {
  echo "Host Linux VM bundle lacks the three exact FIPS patch packages" >&2
  exit 2
}
ROOT_REALIZED_CARGO_LOCK_SHA256="$(
  python3 "$PATCH_LOCK_VERIFIER" \
    --expected-sha256 "$ROOT/Cargo.lock" "${FIPS_PATCH_PACKAGES[@]}"
)"
LINUX_REALIZED_CARGO_LOCK_SHA256="$(
  python3 "$PATCH_LOCK_VERIFIER" \
    --expected-sha256 "$ROOT/linux/Cargo.lock" "${FIPS_PATCH_PACKAGES[@]}"
)"
DOWNLOAD_CACHE_ID="$(
  printf '%s:%s\n' \
    "$ROOT_REALIZED_CARGO_LOCK_SHA256" \
    "$LINUX_REALIZED_CARGO_LOCK_SHA256" \
    | shasum -a 256 | awk '{print $1}'
)"
DOWNLOAD_CACHE_PARENT="$CACHE_ROOT/build-cache/cargo-archives"
DOWNLOAD_CACHE_DIR="$DOWNLOAD_CACHE_PARENT/$DOWNLOAD_CACHE_ID"
CARGO_CACHE_VERIFIER="$ROOT/scripts/host_linux_cargo_archive_cache.py"
SOURCE_AUDITOR="$ROOT/scripts/verify_host_linux_build_source.py"
[[ -x "$CARGO_CACHE_VERIFIER" && -x "$SOURCE_AUDITOR" ]] || {
  echo "Host Linux VM bundle cache/source verifier is missing" >&2
  exit 2
}
for candidate_file in \
  scripts/host_linux_cargo_archive_cache.py \
  scripts/host_linux_package_content.py \
  scripts/lib-host-linux-builder-isolation.sh \
  scripts/lib-host-linux-native-builder.sh \
  scripts/verify-host-linux-vm-bundle.py \
  scripts/verify_host_linux_build_source.py
do
  require_exact_candidate_file "$candidate_file"
done
TEMP_DIR=""
CONTAINER_NAME="nvpn-linux-bundle-${BUILD_CACHE_ID:0:24}"
HOST_BUILD_LOCK_HELD=0
TARGET_VOLUME_OWNED=0

cleanup() {
  local status="$?" cleanup_failed=0
  trap - EXIT HUP INT TERM
  if [[ "$BUILDER_MODE" == "local-docker" \
    && "$HOST_BUILD_LOCK_HELD" == "1" ]]
  then
    host_linux_builder_stop_container \
      "$CONTAINER_NAME" "$BUILD_CACHE_ID" \
      || cleanup_failed=1
    if [[ "$TARGET_VOLUME_OWNED" == "1" ]]; then
      host_linux_builder_remove_target_volume \
        "$TARGET_VOLUME_NAME" "$BUILD_CACHE_ID" \
        "$TARGET_CACHE_GENERATION" || cleanup_failed=1
    fi
  fi
  host_linux_native_builder_cleanup_remote || cleanup_failed=1
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    find "$TEMP_DIR" -xdev -depth -mindepth 1 -delete || cleanup_failed=1
    rmdir "$TEMP_DIR" || cleanup_failed=1
  fi
  if [[ "$status" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    status=1
  fi
  exit "$status"
}

terminate() {
  local status="$1"
  if [[ "$BUILDER_MODE" == "local-docker" \
    && "$HOST_BUILD_LOCK_HELD" == "1" ]]
  then
    host_linux_builder_stop_container \
      "$CONTAINER_NAME" "$BUILD_CACHE_ID" || true
    if [[ "$TARGET_VOLUME_OWNED" == "1" ]]; then
      host_linux_builder_remove_target_volume \
        "$TARGET_VOLUME_NAME" "$BUILD_CACHE_ID" \
        "$TARGET_CACHE_GENERATION" || true
    fi
  fi
  host_linux_native_builder_cleanup_remote || true
  exit "$status"
}

trap cleanup EXIT
trap 'terminate 129' HUP
trap 'terminate 130' INT
trap 'terminate 143' TERM

verify_bundle() {
  [[ -x "$VERIFIER" && -d "$BUNDLE_DIR" && -f "$RECEIPT" ]] || return 1
  python3 "$VERIFIER" \
    "$BUNDLE_DIR" \
    "$RECEIPT" \
    "$APP_GIT_SHA" \
    "$APP_GIT_TREE" \
    "$APP_VERSION" \
    "$RELEASE_JOIN_FIPS_SHA" \
    "$RELEASE_JOIN_FIPS_TREE" \
    "$RELEASE_JOIN_FIPS_VERSION" \
    "$ROOT_CARGO_LOCK_SHA256" \
    "$ROOT_REALIZED_CARGO_LOCK_SHA256" \
    "$LINUX_CARGO_LOCK_SHA256" \
    "$LINUX_REALIZED_CARGO_LOCK_SHA256" \
    "$TARGET" \
    "$BUILDER_MODE" \
    "$RUST_TOOLCHAIN" \
    "$DOCKERFILE_SHA256" \
    "$CONTAINER_PAYLOAD_SHA256" \
    "${FIPS_PATCH_PACKAGES[@]}" \
    >/dev/null
}

if verify_bundle; then
  printf '%s\n' "$BUNDLE_DIR"
  exit 0
fi

[[ -x /usr/bin/lockf ]] || {
  echo "Host Linux VM bundle builder requires macOS /usr/bin/lockf." >&2
  exit 2
}
exec 9>"$HOST_BUILD_LOCK"
chmod 0600 "$HOST_BUILD_LOCK"
/usr/bin/lockf 9
HOST_BUILD_LOCK_HELD=1

# A second process can finish the exact bundle while this process waits for
# the kernel lock. Re-verify under the lock before spending any build work.
if verify_bundle; then
  printf '%s\n' "$BUNDLE_DIR"
  exit 0
fi

# A SIGKILL cannot run a shell trap. The kernel lock is still released, so
# remove any daemon-owned container carrying this cache identity before the
# persistent targets can be mounted by the next build.
if [[ "$BUILDER_MODE" == "local-docker" ]]; then
  host_linux_builder_stop_container "$CONTAINER_NAME" "$BUILD_CACHE_ID"
  # rustc dependency outputs must stay on Docker's native Linux filesystem.
  # Docker Desktop bind mounts can expose a completed dependency to Cargo
  # before a parallel rustc can read its metadata.
  host_linux_builder_create_fresh_target_volume \
    "$TARGET_VOLUME_NAME" "$BUILD_CACHE_ID" "$TARGET_CACHE_GENERATION"
  TARGET_VOLUME_OWNED=1
fi

TEMP_DIR="$(mktemp -d "$CACHE_ROOT/.host-linux-vm-bundle.XXXXXX")"
mkdir -p \
  "$TEMP_DIR/source" \
  "$TEMP_DIR/build" \
  "$TEMP_DIR/output" \
  "$TEMP_DIR/final" \
  "$TEMP_DIR/docker-context" \
  "$TEMP_DIR/cargo-home" \
  "$TEMP_DIR/package-root-target" \
  "$TEMP_DIR/package-linux-target" \
  "$DOWNLOAD_CACHE_PARENT"
[[ -d "$DOWNLOAD_CACHE_PARENT" && ! -L "$DOWNLOAD_CACHE_PARENT" ]] || {
  echo "Host Linux Cargo archive cache parent is unsafe" >&2
  exit 2
}
chmod 0700 \
  "$TEMP_DIR/cargo-home" \
  "$TEMP_DIR/package-root-target" \
  "$TEMP_DIR/package-linux-target" \
  "$DOWNLOAD_CACHE_PARENT"
git clone --no-hardlinks --quiet "$ROOT" "$TEMP_DIR/source/app"
git -C "$TEMP_DIR/source/app" checkout --detach --quiet "$APP_GIT_SHA"
git -C "$TEMP_DIR/source/app" clean -ffdx >/dev/null
git clone --no-hardlinks --quiet "$NVPN_FIPS_REPO_PATH" "$TEMP_DIR/source/fips"
git -C "$TEMP_DIR/source/fips" checkout --detach --quiet "$RELEASE_JOIN_FIPS_SHA"
git -C "$TEMP_DIR/source/fips" clean -ffdx >/dev/null
python3 "$SOURCE_AUDITOR" --exact \
  "$TEMP_DIR/source/app" "$APP_GIT_SHA" "$APP_GIT_TREE" >/dev/null
python3 "$SOURCE_AUDITOR" --exact \
  "$TEMP_DIR/source/fips" \
  "$RELEASE_JOIN_FIPS_SHA" "$RELEASE_JOIN_FIPS_TREE" >/dev/null
[[ "$(shasum -a 256 "$TEMP_DIR/source/app/Cargo.lock" | awk '{ print $1 }')" \
  == "$ROOT_CARGO_LOCK_SHA256" ]]
[[ "$(shasum -a 256 "$TEMP_DIR/source/app/linux/Cargo.lock" | awk '{ print $1 }')" \
  == "$LINUX_CARGO_LOCK_SHA256" ]]

if [[ "$BUILDER_MODE" == "remote-native" ]]; then
  host_linux_native_builder_run \
    "$TEMP_DIR" \
    "$APP_GIT_SHA" "$APP_GIT_TREE" \
    "$RELEASE_JOIN_FIPS_SHA" "$RELEASE_JOIN_FIPS_TREE" \
    "$RUST_TOOLCHAIN" \
    "$BUILD_CACHE_ID" "$TARGET_CACHE_GENERATION" \
    "$TARGET_VOLUME_NAME" "$CONTAINER_NAME" \
    "$ROOT_REALIZED_CARGO_LOCK_SHA256" \
    "$LINUX_REALIZED_CARGO_LOCK_SHA256" \
    "$SOURCE_DATE_EPOCH" \
    "$DOCKERFILE_SHA256" "$CONTAINER_PAYLOAD_SHA256"
else
  git clone --no-hardlinks --quiet \
    "$TEMP_DIR/source/app" "$TEMP_DIR/build/app"
  git -C "$TEMP_DIR/build/app" checkout --detach --quiet "$APP_GIT_SHA"
  git -C "$TEMP_DIR/build/app" clean -ffdx >/dev/null
  python3 "$SOURCE_AUDITOR" --exact \
    "$TEMP_DIR/build/app" "$APP_GIT_SHA" "$APP_GIT_TREE" >/dev/null
  python3 "$PATCH_LOCK_VERIFIER" \
    --materialize "$ROOT/Cargo.lock" "$TEMP_DIR/root-realized.lock" \
    "${FIPS_PATCH_PACKAGES[@]}" >/dev/null
  python3 "$PATCH_LOCK_VERIFIER" \
    --materialize "$ROOT/linux/Cargo.lock" "$TEMP_DIR/linux-realized.lock" \
    "${FIPS_PATCH_PACKAGES[@]}" >/dev/null
  python3 "$CARGO_CACHE_VERIFIER" seed \
    "$DOWNLOAD_CACHE_DIR" "$TEMP_DIR/cargo-home" \
    "$TEMP_DIR/root-realized.lock" "$TEMP_DIR/linux-realized.lock"
  IMAGE_TAG="nostr-vpn-linux-vm-gate:ubuntu24.04-rust${RUST_TOOLCHAIN//./-}-${BUILD_CACHE_ID:0:12}"
  docker build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg "RUST_TOOLCHAIN=$RUST_TOOLCHAIN" \
    --file "$TEMP_DIR/source/app/Dockerfile.linux-vm-gate" \
    --tag "$IMAGE_TAG" \
    "$TEMP_DIR/docker-context" \
    >"$TEMP_DIR/docker-build.log"
  CONTAINER_IMAGE_ID="$(
    docker image inspect --format '{{.Id}}' "$IMAGE_TAG"
  )"
  [[ "$CONTAINER_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]

  assert_local_target_empty() {
    docker run --rm \
      --name "$CONTAINER_NAME" \
      --label "to.nostrvpn.release-builder=host-linux-vm-bundle" \
      --label "to.nostrvpn.release-builder-cache=$BUILD_CACHE_ID" \
      --platform "$DOCKER_PLATFORM" \
      --volume "$TARGET_VOLUME_NAME:/target-root" \
      "$CONTAINER_IMAGE_ID" \
      sh -ceu '[ -z "$(find /target-root -mindepth 1 -print -quit)" ]'
    host_linux_builder_stop_container "$CONTAINER_NAME" "$BUILD_CACHE_ID"
  }
  assert_local_target_empty
  docker run --rm \
    --name "$CONTAINER_NAME" \
    --label "to.nostrvpn.release-builder=host-linux-vm-bundle" \
    --label "to.nostrvpn.release-builder-cache=$BUILD_CACHE_ID" \
    --interactive \
    --platform "$DOCKER_PLATFORM" \
    --volume "$TEMP_DIR/build/app:/workspace/app" \
    --volume "$TEMP_DIR/source/fips:/workspace/fips:ro" \
    --volume "$TEMP_DIR/output:/output" \
    --volume "$TEMP_DIR/cargo-home:/cargo-home" \
    --volume "$TARGET_VOLUME_NAME:/target-root" \
    --env CARGO_HOME=/cargo-home \
    --env HOME=/cargo-home \
    --env CARGO_INCREMENTAL=0 \
    --env CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    --env "NVPN_BUILD_GIT_SHA=$APP_GIT_SHA" \
    --env "EXPECTED_ROOT_REALIZED_CARGO_LOCK_SHA256=$ROOT_REALIZED_CARGO_LOCK_SHA256" \
    --env "EXPECTED_LINUX_REALIZED_CARGO_LOCK_SHA256=$LINUX_REALIZED_CARGO_LOCK_SHA256" \
    --env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --env TZ=UTC \
    --env LC_ALL=C.UTF-8 \
    "$CONTAINER_IMAGE_ID" \
    /workspace/app/scripts/build-host-linux-vm-bundle-in-container.sh \
    realize
  python3 "$SOURCE_AUDITOR" \
    "$TEMP_DIR/source/app" "$TEMP_DIR/build/app" \
    "$APP_GIT_SHA" "$APP_GIT_TREE" \
    "$ROOT_REALIZED_CARGO_LOCK_SHA256" \
    "$LINUX_REALIZED_CARGO_LOCK_SHA256"
  python3 "$CARGO_CACHE_VERIFIER" store \
    "$DOWNLOAD_CACHE_DIR" "$TEMP_DIR/cargo-home" \
    "$TEMP_DIR/build/app/Cargo.lock" \
    "$TEMP_DIR/build/app/linux/Cargo.lock"
  host_linux_builder_remove_target_volume \
    "$TARGET_VOLUME_NAME" "$BUILD_CACHE_ID" "$TARGET_CACHE_GENERATION"
  host_linux_builder_create_fresh_target_volume \
    "$TARGET_VOLUME_NAME" "$BUILD_CACHE_ID" "$TARGET_CACHE_GENERATION"
  assert_local_target_empty
  mkdir "$TEMP_DIR/build/app/target" "$TEMP_DIR/build/app/linux/target"
  docker run --rm \
    --name "$CONTAINER_NAME" \
    --label "to.nostrvpn.release-builder=host-linux-vm-bundle" \
    --label "to.nostrvpn.release-builder-cache=$BUILD_CACHE_ID" \
    --interactive \
    --platform "$DOCKER_PLATFORM" \
    --volume "$TEMP_DIR/build/app:/workspace/app:ro" \
    --volume "$TEMP_DIR/source/fips:/workspace/fips:ro" \
    --volume "$TEMP_DIR/output:/output" \
    --volume "$TEMP_DIR/cargo-home:/cargo-home" \
    --volume "$TARGET_VOLUME_NAME:/target-root" \
    --volume "$TEMP_DIR/package-root-target:/workspace/app/target" \
    --volume "$TEMP_DIR/package-linux-target:/workspace/app/linux/target" \
    --env CARGO_HOME=/cargo-home \
    --env HOME=/cargo-home \
    --env CARGO_INCREMENTAL=0 \
    --env CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    --env "NVPN_BUILD_GIT_SHA=$APP_GIT_SHA" \
    --env "EXPECTED_ROOT_REALIZED_CARGO_LOCK_SHA256=$ROOT_REALIZED_CARGO_LOCK_SHA256" \
    --env "EXPECTED_LINUX_REALIZED_CARGO_LOCK_SHA256=$LINUX_REALIZED_CARGO_LOCK_SHA256" \
    --env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --env TZ=UTC \
    --env LC_ALL=C.UTF-8 \
    "$CONTAINER_IMAGE_ID" \
    /workspace/app/scripts/build-host-linux-vm-bundle-in-container.sh \
    build
  rmdir "$TEMP_DIR/build/app/linux/target" "$TEMP_DIR/build/app/target"
  python3 "$SOURCE_AUDITOR" \
    "$TEMP_DIR/source/app" "$TEMP_DIR/build/app" \
    "$APP_GIT_SHA" "$APP_GIT_TREE" \
    "$ROOT_REALIZED_CARGO_LOCK_SHA256" \
    "$LINUX_REALIZED_CARGO_LOCK_SHA256"
  host_linux_builder_remove_target_volume \
    "$TARGET_VOLUME_NAME" "$BUILD_CACHE_ID" "$TARGET_CACHE_GENERATION"
  TARGET_VOLUME_OWNED=0
  python3 - \
    "$TEMP_DIR/output/builder-provenance.json" \
    "$CONTAINER_IMAGE_ID" \
    "$DOCKERFILE_SHA256" \
    "$CONTAINER_PAYLOAD_SHA256" \
    "$(uname -m)" <<'PY'
import json
import os
import pathlib
import re
import sys

output, image_id, dockerfile_sha, payload_sha, architecture = sys.argv[1:]
if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
    raise SystemExit("local Docker builder image identity is invalid")
if architecture not in {"arm64", "x86_64"}:
    raise SystemExit("local Docker builder Mac architecture is invalid")
path = pathlib.Path(output)
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "schema": 1,
            "builderMode": "local-docker",
            "builderHostOs": "Darwin",
            "builderHostArchitecture": architecture,
            "containerImageId": image_id,
            "dockerfileSha256": dockerfile_sha,
            "containerPayloadSha256": payload_sha,
        },
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
fi

python3 "$SOURCE_AUDITOR" --exact \
  "$TEMP_DIR/source/app" "$APP_GIT_SHA" "$APP_GIT_TREE" >/dev/null
python3 "$SOURCE_AUDITOR" --exact \
  "$TEMP_DIR/source/fips" \
  "$RELEASE_JOIN_FIPS_SHA" "$RELEASE_JOIN_FIPS_TREE" >/dev/null
[[ "$(shasum -a 256 "$TEMP_DIR/output/root-Cargo.lock.committed" \
  | awk '{ print $1 }')" == "$ROOT_CARGO_LOCK_SHA256" ]]
[[ "$(shasum -a 256 "$TEMP_DIR/output/linux-Cargo.lock.committed" \
  | awk '{ print $1 }')" == "$LINUX_CARGO_LOCK_SHA256" ]]
[[ "$(<"$TEMP_DIR/output/root-realized-cargo-lock-sha256.txt")" \
  == "$ROOT_REALIZED_CARGO_LOCK_SHA256" ]]
[[ "$(<"$TEMP_DIR/output/linux-realized-cargo-lock-sha256.txt")" \
  == "$LINUX_REALIZED_CARGO_LOCK_SHA256" ]]
for artifact in \
  nvpn \
  desktop_manual_join_e2e_fixture \
  nostr-vpn \
  nvpn-x86_64-unknown-linux-musl
do
  install -m 0555 "$TEMP_DIR/output/$artifact" "$TEMP_DIR/final/$artifact"
done
for artifact in nostr-vpn.deb nvpn-x86_64-unknown-linux-musl.tar.gz; do
  install -m 0444 "$TEMP_DIR/output/$artifact" "$TEMP_DIR/final/$artifact"
done
python3 - \
  "$TEMP_DIR/final/receipt.json" \
  "$TEMP_DIR/final" \
  "$APP_GIT_SHA" \
  "$APP_GIT_TREE" \
  "$APP_VERSION" \
  "$RELEASE_JOIN_FIPS_SHA" \
  "$RELEASE_JOIN_FIPS_TREE" \
  "$RELEASE_JOIN_FIPS_VERSION" \
  "$ROOT_CARGO_LOCK_SHA256" \
  "$ROOT_REALIZED_CARGO_LOCK_SHA256" \
  "$LINUX_CARGO_LOCK_SHA256" \
  "$LINUX_REALIZED_CARGO_LOCK_SHA256" \
  "$TARGET" \
  "$BUILDER_MODE" \
  "$RUST_TOOLCHAIN" \
  "$DOCKERFILE_SHA256" \
  "$CONTAINER_PAYLOAD_SHA256" \
  "${FIPS_PATCH_PACKAGES[@]}" \
  "$SOURCE_DATE_EPOCH" \
  "$TEMP_DIR/output/cli-short-version.txt" \
  "$TEMP_DIR/output/cli-verbose-version.txt" \
  "$TEMP_DIR/output/rustc-version.txt" \
  "$TEMP_DIR/output/cargo-version.txt" \
  "$TEMP_DIR/output/musl-cli-short-version.txt" \
  "$TEMP_DIR/output/musl-cli-verbose-version.txt" \
  "$TEMP_DIR/output/deb-version.txt" \
  "$TEMP_DIR/output/builder-provenance.json" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

(
    receipt_arg,
    bundle_arg,
    app_sha,
    app_tree,
    app_version,
    fips_sha,
    fips_tree,
    fips_version,
    root_cargo_lock_sha256,
    root_realized_cargo_lock_sha256,
    linux_cargo_lock_sha256,
    linux_realized_cargo_lock_sha256,
    target,
    builder_mode,
    rust_toolchain,
    dockerfile_sha256,
    container_payload_sha256,
    fips_core_patch_spec,
    fips_endpoint_patch_spec,
    fips_identity_patch_spec,
    source_epoch,
    cli_short_arg,
    cli_verbose_arg,
    rustc_arg,
    cargo_arg,
    musl_cli_short_arg,
    musl_cli_verbose_arg,
    deb_version_arg,
    builder_provenance_arg,
) = sys.argv[1:]
bundle = pathlib.Path(bundle_arg)
builder = json.loads(
    pathlib.Path(builder_provenance_arg).read_text(encoding="utf-8")
)
expected_builder_keys = {
    "schema",
    "builderMode",
    "builderHostOs",
    "builderHostArchitecture",
    "containerImageId",
    "dockerfileSha256",
    "containerPayloadSha256",
}
if (
    set(builder) != expected_builder_keys
    or builder.get("schema") != 1
    or builder.get("builderMode") != builder_mode
    or builder.get("dockerfileSha256") != dockerfile_sha256
    or builder.get("containerPayloadSha256") != container_payload_sha256
    or re.fullmatch(
        r"sha256:[0-9a-f]{64}", builder.get("containerImageId", "")
    )
    is None
):
    raise SystemExit("unexpected Linux release builder provenance")
if builder_mode == "local-docker":
    built_on_host_mac = True
    built_on_remote_vm = False
    if (
        builder.get("builderHostOs") != "Darwin"
        or builder.get("builderHostArchitecture") != "x86_64"
    ):
        raise SystemExit("invalid local Docker Linux builder provenance")
elif builder_mode == "remote-native":
    built_on_host_mac = False
    built_on_remote_vm = True
    if (
        builder.get("builderHostOs") != "Linux"
        or builder.get("builderHostArchitecture") != "x86_64"
    ):
        raise SystemExit("invalid remote native Linux builder provenance")
else:
    raise SystemExit("unsupported Linux release builder mode")
rustc_version = pathlib.Path(rustc_arg).read_text(encoding="utf-8").strip()
cargo_version = pathlib.Path(cargo_arg).read_text(encoding="utf-8").strip()
if not rustc_version.startswith(f"rustc {rust_toolchain} "):
    raise SystemExit("Linux release builder used the wrong rustc toolchain")
if not cargo_version.startswith(f"cargo {rust_toolchain} "):
    raise SystemExit("Linux release builder used the wrong cargo toolchain")
fips_patch_packages = dict(
    spec.split("=", 1)
    for spec in (
        fips_core_patch_spec,
        fips_endpoint_patch_spec,
        fips_identity_patch_spec,
    )
)
if set(fips_patch_packages) != {
    "nvpn-fips-core",
    "nvpn-fips-endpoint",
    "nvpn-fips-identity",
}:
    raise SystemExit("unexpected exact FIPS patched lock package set")
names = {
    "app": "nostr-vpn",
    "cli": "nvpn",
    "manualJoinFixture": "desktop_manual_join_e2e_fixture",
    "muslCli": "nvpn-x86_64-unknown-linux-musl",
    "debianPackage": "nostr-vpn.deb",
    "muslCliArchive": "nvpn-x86_64-unknown-linux-musl.tar.gz",
}
artifacts = {}
for label, name in names.items():
    path = bundle / name
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    artifacts[label] = {
        "file": name,
        "sha256": digest.hexdigest(),
        "size": path.stat().st_size,
    }
payload = {
    "schema": 2,
    "builderMode": builder_mode,
    "builtOnHostMac": built_on_host_mac,
    "builtOnRemoteVm": built_on_remote_vm,
    "builderHostOs": builder["builderHostOs"],
    "builderHostArchitecture": builder["builderHostArchitecture"],
    "containerImageId": builder["containerImageId"],
    "dockerfileSha256": builder["dockerfileSha256"],
    "containerPayloadSha256": builder["containerPayloadSha256"],
    "appGitSha": app_sha,
    "appGitTree": app_tree,
    "appVersion": app_version,
    "fipsGitSha": fips_sha,
    "fipsGitTree": fips_tree,
    "fipsVersion": fips_version,
    "rootCargoLockSha256": root_cargo_lock_sha256,
    "rootRealizedCargoLockSha256": root_realized_cargo_lock_sha256,
    "linuxCargoLockSha256": linux_cargo_lock_sha256,
    "linuxRealizedCargoLockSha256": linux_realized_cargo_lock_sha256,
    "fipsPatchedLockPackages": fips_patch_packages,
    "target": target,
    "dockerPlatform": "linux/amd64",
    "containerBase": "ubuntu:24.04",
    "sourceDateEpoch": int(source_epoch),
    "rustcVersion": rustc_version,
    "cargoVersion": cargo_version,
    "cliShortVersion": pathlib.Path(cli_short_arg).read_text(encoding="utf-8").strip(),
    "cliVerboseVersion": pathlib.Path(cli_verbose_arg).read_text(encoding="utf-8").strip(),
    "muslCliShortVersion": pathlib.Path(musl_cli_short_arg).read_text(
        encoding="utf-8"
    ).strip(),
    "muslCliVerboseVersion": pathlib.Path(musl_cli_verbose_arg).read_text(
        encoding="utf-8"
    ).strip(),
    "debianPackage": {
        "package": "nostr-vpn",
        "version": pathlib.Path(deb_version_arg).read_text(
            encoding="utf-8"
        ).strip(),
        "architecture": "amd64",
        "appPath": "usr/bin/nostr-vpn",
        "cliPath": "usr/bin/nvpn",
    },
    "muslTarget": "x86_64-unknown-linux-musl",
    "cargoDebVersion": "3.7.0",
    "artifacts": artifacts,
}
pathlib.Path(receipt_arg).write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

python3 "$VERIFIER" \
  "$TEMP_DIR/final" \
  "$TEMP_DIR/final/receipt.json" \
  "$APP_GIT_SHA" \
  "$APP_GIT_TREE" \
  "$APP_VERSION" \
  "$RELEASE_JOIN_FIPS_SHA" \
  "$RELEASE_JOIN_FIPS_TREE" \
  "$RELEASE_JOIN_FIPS_VERSION" \
  "$ROOT_CARGO_LOCK_SHA256" \
  "$ROOT_REALIZED_CARGO_LOCK_SHA256" \
  "$LINUX_CARGO_LOCK_SHA256" \
  "$LINUX_REALIZED_CARGO_LOCK_SHA256" \
  "$TARGET" \
  "$BUILDER_MODE" \
  "$RUST_TOOLCHAIN" \
  "$DOCKERFILE_SHA256" \
  "$CONTAINER_PAYLOAD_SHA256" \
  "${FIPS_PATCH_PACKAGES[@]}" \
  >/dev/null
release_join_assert_app_unchanged "$APP_GIT_SHA" "$APP_GIT_TREE"
release_join_assert_fips_unchanged

if [[ -d "$BUNDLE_DIR" ]]; then
  find "$BUNDLE_DIR" -xdev -depth -mindepth 1 -delete
  rmdir "$BUNDLE_DIR"
fi
mv "$TEMP_DIR/final" "$BUNDLE_DIR"
find "$TEMP_DIR" -xdev -depth -mindepth 1 -delete
rmdir "$TEMP_DIR"
TEMP_DIR=""
verify_bundle
printf '%s\n' "$BUNDLE_DIR"
