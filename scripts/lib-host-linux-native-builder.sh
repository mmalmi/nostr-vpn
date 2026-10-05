#!/usr/bin/env bash

# Mac-side orchestration for the explicit native x86_64 Linux release builder.
# The remote receives immutable exact-source bundles and returns one fixed
# regular-file tar. It never installs or launches nVPN on the builder host.

NVPN_HOST_LINUX_NATIVE_REMOTE_DIR=""
NVPN_HOST_LINUX_NATIVE_SSH=()
NVPN_HOST_LINUX_NATIVE_SCP=()

host_linux_native_builder_configured() {
  [[ -n "${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST:-}" ]]
}

host_linux_native_builder_commands() {
  local host="${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST:-}"
  local jump="${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_JUMP:-}"
  local proxy="${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND:-}"
  [[ -n "$host" && "$host" != -* \
    && "$host" =~ ^[A-Za-z0-9_.@%-]+$ ]] || {
    echo "Remote native Linux builder host is invalid" >&2
    return 2
  }
  [[ -z "$jump" || ( "$jump" != -* \
    && "$jump" =~ ^[A-Za-z0-9_.@:%-]+$ ) ]] || {
    echo "Remote native Linux builder jump host is invalid" >&2
    return 2
  }
  [[ -z "$proxy" || ( "$proxy" != *$'\n'* && "$proxy" != *$'\r'* ) ]] || {
    echo "Remote native Linux builder proxy command is invalid" >&2
    return 2
  }
  [[ -z "$jump" || -z "$proxy" ]] || {
    echo "Remote native Linux builder accepts either jump or proxy, not both" >&2
    return 2
  }

  NVPN_HOST_LINUX_NATIVE_SSH=(
    ssh
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o StrictHostKeyChecking=yes
  )
  NVPN_HOST_LINUX_NATIVE_SCP=(
    scp
    -q
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o StrictHostKeyChecking=yes
  )
  if [[ -n "$jump" ]]; then
    NVPN_HOST_LINUX_NATIVE_SSH+=(-J "$jump")
    NVPN_HOST_LINUX_NATIVE_SCP+=(-o "ProxyJump=$jump")
  elif [[ -n "$proxy" ]]; then
    NVPN_HOST_LINUX_NATIVE_SSH+=(-o "ProxyCommand=$proxy")
    NVPN_HOST_LINUX_NATIVE_SCP+=(-o "ProxyCommand=$proxy")
  fi
  NVPN_HOST_LINUX_NATIVE_SSH+=("$host")
}

host_linux_native_builder_cleanup_remote() {
  local remote_dir="${NVPN_HOST_LINUX_NATIVE_REMOTE_DIR:-}"
  [[ -n "$remote_dir" ]] || return 0
  [[ "$remote_dir" \
    =~ ^/[A-Za-z0-9._/-]+/\.cache/nostr-vpn-linux-release-builder/runs/nvpn-linux-native-builder\.[A-Za-z0-9]{6}$ \
    && "$remote_dir" != *"/../"* \
    && "$remote_dir" != *"/./"* \
    && "$remote_dir" != *"//"* ]] || {
    echo "Refusing unsafe remote native builder cleanup" >&2
    return 1
  }
  if [[ "${#NVPN_HOST_LINUX_NATIVE_SSH[@]}" == 0 ]]; then
    host_linux_native_builder_commands || return
  fi
  "${NVPN_HOST_LINUX_NATIVE_SSH[@]}" bash -s -- "$remote_dir" <<'REMOTE'
set -euo pipefail
root="$1"
runs="$HOME/.cache/nostr-vpn-linux-release-builder/runs"
[[ -d "$runs" && -O "$runs" && ! -L "$runs" ]] || exit 2
[[ "$root" == "$runs"/nvpn-linux-native-builder.* \
  && "${root##*/}" =~ ^nvpn-linux-native-builder\.[A-Za-z0-9]{6}$ ]] \
    || exit 2
if [[ -d "$root" && ! -L "$root" ]]; then
  find "$root" -xdev -depth -mindepth 1 -delete
  rmdir "$root"
elif [[ -e "$root" || -L "$root" ]]; then
  exit 2
fi
REMOTE
  NVPN_HOST_LINUX_NATIVE_REMOTE_DIR=""
}

host_linux_native_builder_extract_output() {
  local archive="$1" output="$2"
  python3 - "$archive" "$output" <<'PY'
import os
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
expected = {
    "builder-provenance.json",
    "cargo-version.txt",
    "cli-short-version.txt",
    "cli-verbose-version.txt",
    "deb-version.txt",
    "desktop_manual_join_e2e_fixture",
    "file.txt",
    "linux-Cargo.lock.committed",
    "linux-realized-cargo-lock-sha256.txt",
    "musl-cli-short-version.txt",
    "musl-cli-verbose-version.txt",
    "nostr-vpn",
    "nostr-vpn.deb",
    "nvpn",
    "nvpn-x86_64-unknown-linux-musl",
    "nvpn-x86_64-unknown-linux-musl.tar.gz",
    "root-Cargo.lock.committed",
    "root-realized-cargo-lock-sha256.txt",
    "rustc-version.txt",
}
if not output.is_dir() or output.is_symlink():
    raise SystemExit("remote native output destination is unsafe")
with tarfile.open(archive, "r:") as bundle:
    members = bundle.getmembers()
    names = [member.name for member in members]
    if len(names) != len(set(names)) or set(names) != expected:
        raise SystemExit("remote native output tar has the wrong member set")
    for member in members:
        if (
            not member.isfile()
            or member.issym()
            or member.islnk()
            or pathlib.PurePosixPath(member.name).name != member.name
            or member.size <= 0
        ):
            raise SystemExit("remote native output tar contains an unsafe member")
        source = bundle.extractfile(member)
        if source is None:
            raise SystemExit("remote native output tar member is unreadable")
        destination = output / member.name
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with source, os.fdopen(descriptor, "wb") as target:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
PY
}

host_linux_native_builder_run() {
  local temp_dir="$1" app_sha="$2" app_tree="$3"
  local fips_sha="$4" fips_tree="$5" rust_toolchain="$6"
  local build_cache_id="$7" target_generation="$8" target_volume="$9"
  local container_name="${10}" root_realized_lock="${11}"
  local linux_realized_lock="${12}" source_date_epoch="${13}"
  local dockerfile_sha="${14}" payload_sha="${15}"
  local driver="$ROOT/scripts/host-linux-native-builder-remote.sh"
  local app_bundle="$temp_dir/app.bundle"
  local fips_bundle="$temp_dir/fips.bundle"
  local remote_driver_copy="$temp_dir/remote-driver"
  local output_tar="$temp_dir/remote-output.tar"
  local app_bundle_sha fips_bundle_sha driver_sha remote_dir

  host_linux_builder_resource_args || return
  host_linux_native_builder_commands
  for command in git scp ssh; do
    command -v "$command" >/dev/null 2>&1 || {
      echo "Remote native Linux builder requires $command" >&2
      return 2
    }
  done
  [[ -x "$driver" && ! -L "$driver" ]] || {
    echo "Remote native Linux builder driver is missing" >&2
    return 2
  }

  git -C "$temp_dir/source/app" bundle create "$app_bundle" HEAD
  git -C "$temp_dir/source/fips" bundle create "$fips_bundle" HEAD
  git bundle verify "$app_bundle" >/dev/null
  git bundle verify "$fips_bundle" >/dev/null
  app_bundle_sha="$(shasum -a 256 "$app_bundle" | awk '{print $1}')"
  fips_bundle_sha="$(shasum -a 256 "$fips_bundle" | awk '{print $1}')"
  driver_sha="$(shasum -a 256 "$driver" | awk '{print $1}')"
  install -m 0400 "$driver" "$remote_driver_copy"
  [[ "$(shasum -a 256 "$remote_driver_copy" | awk '{print $1}')" \
    == "$driver_sha" ]]

  remote_dir="$(
    "${NVPN_HOST_LINUX_NATIVE_SSH[@]}" \
      'set -euo pipefail
umask 077
cache="$HOME/.cache"
state="$cache/nostr-vpn-linux-release-builder"
runs="$state/runs"
[[ -d "$cache" && -O "$cache" && ! -L "$cache" ]]
if [[ ! -e "$state" && ! -L "$state" ]]; then mkdir -m 0700 "$state"; fi
[[ -d "$state" && -O "$state" && ! -L "$state" ]]
if [[ ! -e "$runs" && ! -L "$runs" ]]; then mkdir -m 0700 "$runs"; fi
[[ -d "$runs" && -O "$runs" && ! -L "$runs" ]]
chmod 0700 "$state" "$runs"
mktemp -d "$runs/nvpn-linux-native-builder.XXXXXX"'
  )"
  [[ "$remote_dir" \
    =~ ^/[A-Za-z0-9._/-]+/\.cache/nostr-vpn-linux-release-builder/runs/nvpn-linux-native-builder\.[A-Za-z0-9]{6}$ \
    && "$remote_dir" != *"/../"* \
    && "$remote_dir" != *"/./"* \
    && "$remote_dir" != *"//"* ]] || {
    echo "Remote native Linux builder returned an unsafe root" >&2
    return 2
  }
  [[ "$(printf '%s\n' "$remote_dir" | wc -l | tr -d '[:space:]')" == "1" ]]
  NVPN_HOST_LINUX_NATIVE_REMOTE_DIR="$remote_dir"

  "${NVPN_HOST_LINUX_NATIVE_SCP[@]}" \
    "$app_bundle" "$fips_bundle" "$remote_driver_copy" \
    "$NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST:$remote_dir/"

  "${NVPN_HOST_LINUX_NATIVE_SSH[@]}" bash -s -- \
    "$remote_dir" "$driver_sha" \
    "$app_bundle_sha" "$app_sha" "$app_tree" \
    "$fips_bundle_sha" "$fips_sha" "$fips_tree" \
    "$rust_toolchain" "$build_cache_id" "$target_generation" \
    "$target_volume" "$container_name" \
    "$root_realized_lock" "$linux_realized_lock" \
    "$source_date_epoch" "$dockerfile_sha" "$payload_sha" \
    "${NVPN_HOST_LINUX_VM_BUILD_CPUS:--}" \
    "${NVPN_HOST_LINUX_VM_BUILD_MEMORY:--}" \
    "${NVPN_HOST_LINUX_VM_CARGO_JOBS:--}" \
    >"$output_tar" <<'REMOTE'
set -euo pipefail
root="$1"
expected_driver_sha="$2"
shift 2
runs="$HOME/.cache/nostr-vpn-linux-release-builder/runs"
[[ -d "$runs" && -O "$runs" && ! -L "$runs" ]] || exit 2
[[ "$root" == "$runs"/nvpn-linux-native-builder.* \
  && "${root##*/}" =~ ^nvpn-linux-native-builder\.[A-Za-z0-9]{6}$ ]] \
    || exit 2
driver="$root/remote-driver"
[[ -f "$driver" && -O "$driver" && ! -L "$driver" ]]
chmod 0500 "$driver"
[[ "$(sha256sum "$driver" | awk '{print $1}')" == "$expected_driver_sha" ]]
exec "$driver" "$root" "$@"
REMOTE
  [[ -s "$output_tar" && ! -L "$output_tar" ]]

  # The remote driver removes its unique source/output root in its EXIT trap.
  if ! "${NVPN_HOST_LINUX_NATIVE_SSH[@]}" \
    test ! -e "$remote_dir"
  then
    host_linux_native_builder_cleanup_remote
    echo "Remote native Linux builder did not clean its temporary root" >&2
    return 1
  fi
  NVPN_HOST_LINUX_NATIVE_REMOTE_DIR=""

  host_linux_native_builder_extract_output "$output_tar" "$temp_dir/output"
  python3 - \
    "$temp_dir/output/builder-provenance.json" \
    "$dockerfile_sha" "$payload_sha" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
dockerfile_sha, payload_sha = sys.argv[2:]
value = json.loads(path.read_text(encoding="utf-8"))
expected = {
    "schema": 1,
    "builderMode": "remote-native",
    "builderHostOs": "Linux",
    "builderHostArchitecture": "x86_64",
    "dockerfileSha256": dockerfile_sha,
    "containerPayloadSha256": payload_sha,
}
for key, expected_value in expected.items():
    if value.get(key) != expected_value:
        raise SystemExit(f"remote native builder provenance mismatch: {key}")
if (
    set(value) != {*expected, "containerImageId"}
    or re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("containerImageId", ""))
    is None
):
    raise SystemExit("remote native builder provenance shape is invalid")
PY
}
