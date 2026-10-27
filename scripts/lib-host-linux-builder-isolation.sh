#!/usr/bin/env bash

# Exact cleanup for the daemon-owned container used by the host Linux release
# builder. Callers serialize a cache root before invoking this helper.

host_linux_builder_prepare_image() {
  # Candidate sources are mounted separately. Reuse the tooling image across
  # checkouts when its Dockerfile, Rust toolchain, and platform are identical.
  local dockerfile="$1" rust_toolchain="$2" platform="$3" context="$4"
  local key metadata image_id actual_platform actual_key
  key="$(python3 - "$dockerfile" "$rust_toolchain" "$platform" <<'PY'
import hashlib
from pathlib import Path
import sys

source = hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
print(hashlib.sha256(f"v1\n{source}\n{sys.argv[2]}\n{sys.argv[3]}\n".encode()).hexdigest())
PY
  )" || return
  HOST_LINUX_BUILDER_IMAGE_TAG="nostr-vpn-linux-vm-gate:sha256-$key"
  local format='{{.Id}} {{.Os}}/{{.Architecture}} {{index .Config.Labels "to.nostrvpn.builder-environment-key"}}'
  if ! metadata="$(docker image inspect --format "$format" \
    "$HOST_LINUX_BUILDER_IMAGE_TAG" 2>/dev/null)"
  then
    docker build \
      --platform "$platform" \
      --build-arg "RUST_TOOLCHAIN=$rust_toolchain" \
      --label "to.nostrvpn.builder-environment-key=$key" \
      --file "$dockerfile" \
      --tag "$HOST_LINUX_BUILDER_IMAGE_TAG" \
      "$context" >&2 || return
    metadata="$(docker image inspect --format "$format" \
      "$HOST_LINUX_BUILDER_IMAGE_TAG")" || return
  fi
  read -r image_id actual_platform actual_key <<<"$metadata"
  [[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ \
    && "$actual_platform" == "$platform" && "$actual_key" == "$key" \
    && "$metadata" == "$image_id $platform $key" ]] || {
    echo "Cached Linux build environment does not match its content identity" >&2
    return 2
  }
  HOST_LINUX_BUILDER_IMAGE_ID="$image_id"
}

# Operational limits preserve the existing source and receipt validation.
# Keeping the existing environment argument makes this array safe on Bash 3
# even when no limits are configured.
host_linux_builder_resource_args() {
  local cpus="${NVPN_HOST_LINUX_VM_BUILD_CPUS:-}"
  local memory="${NVPN_HOST_LINUX_VM_BUILD_MEMORY:-}"
  local jobs="${NVPN_HOST_LINUX_VM_CARGO_JOBS:-}"
  local tmpfs="${NVPN_HOST_LINUX_VM_TARGET_TMPFS_BYTES:-}"
  local retain="${NVPN_HOST_LINUX_VM_RETAIN_TARGET:-0}"
  local target_bytes="${NVPN_HOST_LINUX_VM_TARGET_MAX_BYTES:-}"
  [[ -z "$cpus" || "$cpus" =~ ^[1-9][0-9]*$ ]] \
    && [[ -z "$memory" || "$memory" =~ ^[1-9][0-9]*[kKmMgG]?$ ]] \
    && [[ -z "$jobs" || "$jobs" =~ ^[1-9][0-9]*$ ]] \
    && [[ -z "$tmpfs" || ( "$tmpfs" =~ ^[1-9][0-9]*$ && -n "$memory" ) ]] || {
    echo "Linux builder limits must be positive; tmpfs requires a memory limit" >&2
    return 2
  }
  [[ "$retain" == 0 || "$retain" == 1 ]] || return 2
  if [[ "$retain" == 1 ]]; then
    [[ -z "$tmpfs" && -n "$cpus" && -n "$memory" && -n "$jobs" \
      && "$target_bytes" =~ ^[1-9][0-9]{0,13}$ ]] || {
      echo "Retained targets require CPU/memory/jobs/byte bounds and disk backing" >&2
      return 2
    }
  fi
  HOST_LINUX_BUILDER_RESOURCE_ARGS=(--env CARGO_INCREMENTAL=0)
  if [[ -n "$cpus" ]]; then
    HOST_LINUX_BUILDER_RESOURCE_ARGS+=(--cpus "$cpus")
  fi
  if [[ -n "$memory" ]]; then
    HOST_LINUX_BUILDER_RESOURCE_ARGS+=(--memory "$memory" --memory-swap "$memory")
  fi
  if [[ -n "$jobs" ]]; then
    HOST_LINUX_BUILDER_RESOURCE_ARGS+=(--env "CARGO_BUILD_JOBS=$jobs")
  fi
}

host_linux_builder_container_matches() {
  local container_id="$1"
  local expected_cache_id="$2"
  local role cache_id
  role="$(
    docker container inspect \
      --format '{{ index .Config.Labels "to.nostrvpn.release-builder" }}' \
      "$container_id"
  )" || return
  cache_id="$(
    docker container inspect \
      --format '{{ index .Config.Labels "to.nostrvpn.release-builder-cache" }}' \
      "$container_id"
  )" || return
  [[ "$role" == "host-linux-vm-bundle" \
    && "$cache_id" == "$expected_cache_id" ]]
}

host_linux_builder_stop_container() {
  local container_name="$1"
  local expected_cache_id="$2"
  local container_id="$container_name"

  [[ -n "$container_id" ]] || return 0
  if ! docker container inspect "$container_id" >/dev/null 2>&1; then
    return 0
  fi
  if ! host_linux_builder_container_matches \
    "$container_id" "$expected_cache_id"
  then
    echo "Refusing to remove mismatched Linux builder container: $container_id" >&2
    return 1
  fi
  docker rm --force "$container_id" >/dev/null
  ! docker container inspect "$container_id" >/dev/null 2>&1
}

host_linux_builder_target_volume_matches() {
  local volume_name="$1"
  local expected_cache_id="$2"
  local expected_generation="$3"
  local role cache_id generation driver mountpoint
  role="$(
    docker volume inspect \
      --format '{{ index .Labels "to.nostrvpn.release-builder" }}' \
      "$volume_name"
  )" || return
  cache_id="$(
    docker volume inspect \
      --format '{{ index .Labels "to.nostrvpn.release-builder-cache" }}' \
      "$volume_name"
  )" || return
  generation="$(
    docker volume inspect \
      --format '{{ index .Labels "to.nostrvpn.release-builder-generation" }}' \
      "$volume_name"
  )" || return
  driver="$(docker volume inspect --format '{{ .Driver }}' "$volume_name")" \
    || return
  mountpoint="$(
    docker volume inspect --format '{{ .Mountpoint }}' "$volume_name"
  )" || return
  [[ "$role" == "host-linux-vm-bundle-target" \
    && "$cache_id" == "$expected_cache_id" \
    && "$generation" == "$expected_generation" \
    && "$driver" == "local" \
    && "$mountpoint" == /* ]]
}

host_linux_builder_remove_target_volume() {
  local volume_name="$1"
  local expected_cache_id="$2"
  local expected_generation="$3"
  if ! docker volume inspect "$volume_name" >/dev/null 2>&1; then
    return 0
  fi
  if ! host_linux_builder_target_volume_matches \
    "$volume_name" "$expected_cache_id" "$expected_generation"
  then
    echo "Refusing mismatched Linux builder target volume: $volume_name" >&2
    return 1
  fi
  host_linux_builder_assert_target_unused "$volume_name" || return
  docker volume rm "$volume_name" >/dev/null
  ! docker volume inspect "$volume_name" >/dev/null 2>&1
}

# Call only under the established builder lock. Include stopped containers:
# they may still belong to another validation lane and retain a mount claim.
host_linux_builder_assert_target_unused() {
  local users
  users="$(docker ps --all --quiet --filter "volume=$1")" || return
  [[ -z "$users" ]] || {
    echo "Linux builder target still has a container owner: $1" >&2
    return 2
  }
}

# This is deliberately one stable slot per owner, not a new cache per retry.
# A compatibility mismatch preserves the old target and fails closed. Retiring
# it is a separate owner decision using remove_target_volume under this lock.
host_linux_builder_prepare_retained_target() {
  local cache_id="$1" image="$2" rust="$3" root_lock="$4" linux_lock="$5"
  local payload="$6" probe_name="$7" toolchain compatibility options
  host_linux_builder_resource_args || return
  [[ "${NVPN_HOST_LINUX_VM_RETAIN_TARGET:-0}" == 1 \
    && "$cache_id" =~ ^[0-9a-f]{64}$ \
    && "$image" =~ ^sha256:[0-9a-f]{64}$ \
    && "$rust" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
    && "$root_lock" =~ ^[0-9a-f]{64}$ \
    && "$linux_lock" =~ ^[0-9a-f]{64}$ \
    && "$payload" =~ ^[0-9a-f]{64}$ ]] || return 2
  # Bind the actual tools, not just the requested Rust version. The immutable
  # image and payload also bind linker, target set, Cargo profiles and flags.
  toolchain="$(docker run --rm --network none --read-only --name "$probe_name" \
    --label "to.nostrvpn.release-builder=host-linux-vm-bundle" \
    --label "to.nostrvpn.release-builder-cache=$cache_id" \
    --platform linux/amd64 "${HOST_LINUX_BUILDER_RESOURCE_ARGS[@]}" \
    "$image" sh -ceu 'rustc -vV; cargo -V; musl-gcc -dumpmachine; musl-gcc -dumpversion')" || return
  host_linux_builder_stop_container "$probe_name" "$cache_id" || return
  [[ "$toolchain" == "rustc $rust "* ]] || {
    echo "Retained target actual Rust toolchain differs" >&2
    return 2
  }
  compatibility="$(python3 - "$image" "$toolchain" "$root_lock" \
    "$linux_lock" "$payload" "$(id -u):$(id -g)" <<'PY'
import hashlib, json, sys
print(hashlib.sha256(json.dumps(
    ['native-linux-target-v1', 'x86_64-unknown-linux-gnu',
     'x86_64-unknown-linux-musl', 'CARGO_INCREMENTAL=0', *sys.argv[1:]],
    separators=(',', ':')).encode()).hexdigest())
PY
  )" || return
  HOST_LINUX_RETAINED_VOLUME="nvpn-linux-retained-${cache_id:0:24}"
  HOST_LINUX_RETAINED_GENERATION="retained-v1-$compatibility"
  HOST_LINUX_RETAINED_REUSED=0
  if docker volume inspect "$HOST_LINUX_RETAINED_VOLUME" >/dev/null 2>&1; then
    host_linux_builder_target_volume_matches "$HOST_LINUX_RETAINED_VOLUME" \
      "$cache_id" "$HOST_LINUX_RETAINED_GENERATION" || {
      echo "Retained target compatibility mismatch; preserve it for owner review" >&2
      return 2
    }
    options="$(docker volume inspect --format '{{json .Options}}' \
      "$HOST_LINUX_RETAINED_VOLUME")" || return
    [[ "$options" == null || "$options" == '{}' ]] || return 2
    host_linux_builder_assert_target_unused "$HOST_LINUX_RETAINED_VOLUME" || return
    HOST_LINUX_RETAINED_REUSED=1
  else
    docker volume create --driver local \
      --label "to.nostrvpn.release-builder=host-linux-vm-bundle-target" \
      --label "to.nostrvpn.release-builder-cache=$cache_id" \
      --label "to.nostrvpn.release-builder-generation=$HOST_LINUX_RETAINED_GENERATION" \
      "$HOST_LINUX_RETAINED_VOLUME" >/dev/null || return
    host_linux_builder_target_volume_matches "$HOST_LINUX_RETAINED_VOLUME" \
      "$cache_id" "$HOST_LINUX_RETAINED_GENERATION" || return
  fi
}

# Admission and completion bounds, not a filesystem quota. The execution owner
# must still enforce its physical-host growth/floor guard during the build.
# Exceeding the bound stops reuse/acceptance; it never triggers data deletion.
host_linux_builder_check_retained_target_size() {
  local volume="$1" image="$2" cache_id="$3" probe_name="$4" bytes
  host_linux_builder_resource_args || return
  host_linux_builder_assert_target_unused "$volume" || return
  bytes="$(docker run --rm --network none --read-only --name "$probe_name" \
    --label "to.nostrvpn.release-builder=host-linux-vm-bundle" \
    --label "to.nostrvpn.release-builder-cache=$cache_id" \
    --platform linux/amd64 "${HOST_LINUX_BUILDER_RESOURCE_ARGS[@]}" \
    --mount "type=volume,src=$volume,dst=/target,readonly" \
    "$image" sh -ceu 'du -s -B1 /target | cut -f1')" || return
  host_linux_builder_stop_container "$probe_name" "$cache_id" || return
  [[ "$bytes" =~ ^[0-9]{1,14}$ \
    && "$bytes" -le "$NVPN_HOST_LINUX_VM_TARGET_MAX_BYTES" ]] || {
    echo "Retained target exceeds its byte bound; preserved for owner review" >&2
    return 2
  }
  printf 'Retained target %s uses %s bytes (limit %s)\n' \
    "$volume" "$bytes" "$NVPN_HOST_LINUX_VM_TARGET_MAX_BYTES" >&2
}

host_linux_builder_create_fresh_target_volume() {
  local volume_name="$1"
  local expected_cache_id="$2"
  local expected_generation="$3"
  local tmpfs="${NVPN_HOST_LINUX_VM_TARGET_TMPFS_BYTES:-}"
  local -a storage_args=(--driver local)
  host_linux_builder_resource_args || return
  if [[ -n "$tmpfs" ]]; then
    # Docker may unmount this scratch volume between phases. Set ownership in
    # the mount options so each fresh mount is writable by the build identity.
    storage_args+=(--opt type=tmpfs --opt device=tmpfs \
      --opt "o=size=$tmpfs,mode=0700,uid=$(id -u),gid=$(id -g)")
  fi
  host_linux_builder_remove_target_volume \
    "$volume_name" "$expected_cache_id" "$expected_generation"
  docker volume create \
    "${storage_args[@]}" \
    --label "to.nostrvpn.release-builder=host-linux-vm-bundle-target" \
    --label "to.nostrvpn.release-builder-cache=$expected_cache_id" \
    --label "to.nostrvpn.release-builder-generation=$expected_generation" \
    "$volume_name" >/dev/null
  if ! host_linux_builder_target_volume_matches \
    "$volume_name" "$expected_cache_id" "$expected_generation"
  then
    echo "Fresh Linux builder target volume is invalid: $volume_name" >&2
    return 1
  fi
}
