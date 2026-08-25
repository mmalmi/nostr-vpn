#!/usr/bin/env bash
# Shared immutable host-bundle import lifecycle for native Ubuntu UI gates.

NVPN_UBUNTU_IMPORTED_DIR=""
NVPN_UBUNTU_IMPORTED_APP=""
NVPN_UBUNTU_IMPORTED_CLI=""
NVPN_UBUNTU_IMPORTED_FIXTURE=""
NVPN_UBUNTU_IMPORTED_MUSL_CLI=""
NVPN_UBUNTU_IMPORTED_MUSL_ARCHIVE=""
NVPN_UBUNTU_IMPORTED_DEB=""
NVPN_UBUNTU_IMPORTED_RECEIPT=""
NVPN_UBUNTU_IMPORTED_PACKAGE_RECEIPT=""
NVPN_UBUNTU_IMPORTED=0
NVPN_UBUNTU_IMPORT_LOCK_PID=""
NVPN_UBUNTU_IMPORT_LOCK_TEMP=""

ubuntu_vm_import_error() {
  echo "Ubuntu VM imported release failed: $*" >&2
}

ubuntu_vm_import_ssh_command() {
  NVPN_UBUNTU_IMPORT_SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10)
  if [[ -n "${NVPN_UBUNTU_SSH_PROXY_COMMAND:-}" ]]; then
    NVPN_UBUNTU_IMPORT_SSH+=(-o "ProxyCommand=$NVPN_UBUNTU_SSH_PROXY_COMMAND")
  elif [[ -n "${NVPN_UBUNTU_SSH_JUMP:-}" ]]; then
    NVPN_UBUNTU_IMPORT_SSH+=(-J "$NVPN_UBUNTU_SSH_JUMP")
  fi
  NVPN_UBUNTU_IMPORT_SSH+=("$SSH_HOST")
}

ubuntu_vm_import_scp_command() {
  NVPN_UBUNTU_IMPORT_SCP=(scp -q -o BatchMode=yes -o ConnectTimeout=10)
  if [[ -n "${NVPN_UBUNTU_SSH_PROXY_COMMAND:-}" ]]; then
    NVPN_UBUNTU_IMPORT_SCP+=(-o "ProxyCommand=$NVPN_UBUNTU_SSH_PROXY_COMMAND")
  elif [[ -n "${NVPN_UBUNTU_SSH_JUMP:-}" ]]; then
    NVPN_UBUNTU_IMPORT_SCP+=(-J "$NVPN_UBUNTU_SSH_JUMP")
  fi
}

ubuntu_vm_import_lock_holder_alive() {
  local pid="${1:-}"
  local state
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  state="$(
    ps -o stat= -p "$pid" 2>/dev/null \
      | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]].*$//'
  )"
  [[ -n "$state" && "$state" != Z* ]]
}

ubuntu_vm_acquire_import_lock() {
  if [[ -n "$NVPN_UBUNTU_IMPORT_LOCK_PID" ]]; then
    if ubuntu_vm_import_lock_holder_alive "$NVPN_UBUNTU_IMPORT_LOCK_PID"; then
      return 0
    fi
    ubuntu_vm_import_error "recorded VM import lock holder is no longer alive"
    return 1
  fi
  [[ ! -e /dev/fd/8 ]] || {
    ubuntu_vm_import_error "host file descriptor 8 is already in use"
    return 1
  }
  ubuntu_vm_import_ssh_command
  local temp fifo ready error pid
  temp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ubuntu-import-lock.XXXXXX")" \
    || return 1
  fifo="$temp/hold"
  ready="$temp/ready"
  error="$temp/error"
  mkfifo "$fifo" || {
    rm -rf "$temp"
    return 1
  }
  exec 8<>"$fifo"
  (
    exec 8>&-
    exec "${NVPN_UBUNTU_IMPORT_SSH[@]}" \
      bash "$GUEST_REPO/scripts/ubuntu-vm-import-lock-holder.sh" \
      <"$fifo" >"$ready" 2>"$error"
  ) &
  pid="$!"
  local attempt=0
  while ((attempt < 300)); do
    if grep -Fxq UBUNTU_IMPORT_LIFECYCLE_LOCK_READY "$ready" 2>/dev/null \
      && ubuntu_vm_import_lock_holder_alive "$pid"
    then
      NVPN_UBUNTU_IMPORT_LOCK_PID="$pid"
      NVPN_UBUNTU_IMPORT_LOCK_TEMP="$temp"
      return 0
    fi
    ubuntu_vm_import_lock_holder_alive "$pid" || break
    sleep 0.1
    attempt=$((attempt + 1))
  done
  printf 'x' >&8 || true
  exec 8>&-
  if ubuntu_vm_import_lock_holder_alive "$pid"; then
    kill -s TERM "$pid" >/dev/null 2>&1 || true
    attempt=0
    while ((attempt < 20)) \
      && ubuntu_vm_import_lock_holder_alive "$pid"
    do
      sleep 0.05
      attempt=$((attempt + 1))
    done
    if ubuntu_vm_import_lock_holder_alive "$pid"; then
      kill -s KILL "$pid" >/dev/null 2>&1 || true
    fi
  fi
  wait "$pid" >/dev/null 2>&1 || true
  [[ ! -s "$error" ]] || cat "$error" >&2
  rm -rf "$temp"
  ubuntu_vm_import_error "could not acquire the VM import lifecycle lock"
  return 1
}

ubuntu_vm_release_import_lock() {
  local status=0
  local attempt
  if [[ -n "$NVPN_UBUNTU_IMPORT_LOCK_PID" ]]; then
    if ubuntu_vm_import_lock_holder_alive "$NVPN_UBUNTU_IMPORT_LOCK_PID"; then
      printf 'x' >&8 || status=1
    else
      status=1
    fi
    exec 8>&-
    attempt=0
    while ((attempt < 100)) \
      && ubuntu_vm_import_lock_holder_alive "$NVPN_UBUNTU_IMPORT_LOCK_PID"
    do
      sleep 0.05
      attempt=$((attempt + 1))
    done
    if ubuntu_vm_import_lock_holder_alive "$NVPN_UBUNTU_IMPORT_LOCK_PID"; then
      kill -s TERM "$NVPN_UBUNTU_IMPORT_LOCK_PID" >/dev/null 2>&1 || true
      attempt=0
      while ((attempt < 20)) \
        && ubuntu_vm_import_lock_holder_alive "$NVPN_UBUNTU_IMPORT_LOCK_PID"
      do
        sleep 0.05
        attempt=$((attempt + 1))
      done
      if ubuntu_vm_import_lock_holder_alive "$NVPN_UBUNTU_IMPORT_LOCK_PID"; then
        kill -s KILL "$NVPN_UBUNTU_IMPORT_LOCK_PID" >/dev/null 2>&1 || true
      fi
      status=1
    fi
    wait "$NVPN_UBUNTU_IMPORT_LOCK_PID" || status=1
  fi
  if [[ -n "$NVPN_UBUNTU_IMPORT_LOCK_TEMP" ]]; then
    rm -rf "$NVPN_UBUNTU_IMPORT_LOCK_TEMP" || status=1
  fi
  NVPN_UBUNTU_IMPORT_LOCK_PID=""
  NVPN_UBUNTU_IMPORT_LOCK_TEMP=""
  return "$status"
}

ubuntu_vm_recover_stale_imported_release_bundle() {
  ubuntu_vm_import_ssh_command
  if [[ -n "$NVPN_UBUNTU_IMPORT_LOCK_PID" ]]; then
    if ubuntu_vm_import_lock_holder_alive "$NVPN_UBUNTU_IMPORT_LOCK_PID"; then
      "${NVPN_UBUNTU_IMPORT_SSH[@]}" \
        env NVPN_UBUNTU_IMPORT_LOCK_HELD=1 \
        bash "$GUEST_REPO/scripts/ubuntu-vm-recover-stale-import.sh"
    else
      ubuntu_vm_import_error \
        "refusing stale recovery after losing the VM import lifecycle lock"
      return 1
    fi
  else
    "${NVPN_UBUNTU_IMPORT_SSH[@]}" \
      bash "$GUEST_REPO/scripts/ubuntu-vm-recover-stale-import.sh"
  fi
}

ubuntu_vm_committed_lock_evidence() (
  set -euo pipefail
  local root="$1" app_sha="$2" verifier="$3"
  shift 3
  local temp root_lock linux_lock root_sha linux_sha
  local root_realized_sha linux_realized_sha
  temp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-committed-locks.XXXXXX")"
  trap 'rm -rf "$temp"' EXIT
  root_lock="$temp/Cargo.lock"
  linux_lock="$temp/linux-Cargo.lock"
  git -C "$root" show "${app_sha}:Cargo.lock" >"$root_lock"
  git -C "$root" show "${app_sha}:linux/Cargo.lock" >"$linux_lock"
  root_sha="$(shasum -a 256 "$root_lock" | awk '{ print $1 }')"
  linux_sha="$(shasum -a 256 "$linux_lock" | awk '{ print $1 }')"
  root_realized_sha="$(
    python3 "$verifier" --expected-sha256 "$root_lock" "$@"
  )"
  linux_realized_sha="$(
    python3 "$verifier" --expected-sha256 "$linux_lock" "$@"
  )"
  printf '%s\t%s\t%s\t%s\n' \
    "$root_sha" "$root_realized_sha" "$linux_sha" "$linux_realized_sha"
)

ubuntu_vm_import_release_bundle() {
  [[ -n "${ROOT:-}" && -n "${SSH_HOST:-}" && -n "${GUEST_REPO:-}" ]] || {
    ubuntu_vm_import_error "ROOT, SSH_HOST, and GUEST_REPO are required"
    return 1
  }
  [[ "$(uname -s)" == "Darwin" ]] || {
    ubuntu_vm_import_error "bundle import must be controlled by the host Mac"
    return 1
  }
  local release_root bundle receipt app_sha app_tree app_version
  local harness_sha harness_tree
  # load_release_env writes these through Bash's dynamic scope. Keep the
  # product identity local so it cannot replace the caller's harness identity.
  # shellcheck disable=SC2034
  local APP_GIT_SHA APP_GIT_TREE
  local fips_sha fips_tree fips_version target evidence_dir remote_dir
  local lock_evidence root_lock_sha root_realized_lock_sha
  local linux_lock_sha linux_realized_lock_sha
  local builder_mode rust_toolchain dockerfile_sha payload_sha
  local -a fips_patch_packages=()
  local package
  local app_hash app_size cli_hash cli_size fixture_hash fixture_size
  local musl_hash musl_size archive_hash archive_size deb_hash deb_size

  release_root="${NVPN_RELEASE_APP_REPO_PATH:-$ROOT}"
  release_root="$(cd "$release_root" && pwd -P)" || {
    ubuntu_vm_import_error "release app checkout is unavailable"
    return 1
  }
  bundle="${NVPN_HOST_LINUX_VM_BUNDLE_DIR:-}"
  if [[ -z "$bundle" ]]; then
    bundle="$("$release_root/scripts/prepare-host-linux-vm-bundle.sh")" || {
      ubuntu_vm_import_error "host bundle preparation failed"
      return 1
    }
  fi
  [[ "$bundle" == /* && -d "$bundle" && ! -L "$bundle" ]] || {
    ubuntu_vm_import_error "host bundle path is not an absolute real directory"
    return 1
  }
  receipt="$bundle/receipt.json"
  [[ -f "$receipt" && ! -L "$receipt" ]] || {
    ubuntu_vm_import_error "host bundle receipt is missing"
    return 1
  }
  app_sha="$(jq -er '.appGitSha' "$receipt")" || return 1
  app_tree="$(jq -er '.appGitTree' "$receipt")" || return 1
  app_version="$(jq -er '.appVersion' "$receipt")" || return 1
  fips_sha="$(jq -er '.fipsGitSha' "$receipt")" || return 1
  fips_tree="$(jq -er '.fipsGitTree' "$receipt")" || return 1
  fips_version="$(jq -er '.fipsVersion' "$receipt")" || return 1
  builder_mode="$(jq -er '.builderMode' "$receipt")" || return 1
  # shellcheck disable=SC1091
  source "$release_root/scripts/release_common.sh"
  # shellcheck disable=SC1091
  source "$release_root/scripts/lib-mobile-release-join-artifacts.sh"
  load_release_env "$release_root"
  assert_release_checkout_state \
    "$release_root" "$app_sha" "$app_tree" "Ubuntu VM host bundle" || {
    ubuntu_vm_import_error "host bundle differs from the exact app checkout"
    return 1
  }
  harness_sha="$(git -C "$ROOT" rev-parse HEAD)" || return 1
  harness_tree="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')" || return 1
  assert_release_checkout_state \
    "$ROOT" "$harness_sha" "$harness_tree" "Ubuntu VM guest harness" || {
    ubuntu_vm_import_error "guest harness checkout is not committed and clean"
    return 1
  }
  release_join_require_clean_fips || {
    ubuntu_vm_import_error "exact FIPS validation failed before import"
    return 1
  }
  while IFS= read -r package; do
    fips_patch_packages+=("$package")
  done < <(
    python3 "$release_root/scripts/verify-cargo-path-patch-lock.py" \
      --manifest-specs "$NVPN_FIPS_REPO_PATH"
  )
  [[ "${#fips_patch_packages[@]}" == 3 ]] || {
    ubuntu_vm_import_error "exact FIPS patch package set is incomplete"
    return 1
  }
  lock_evidence="$(
    ubuntu_vm_committed_lock_evidence \
      "$release_root" "$app_sha" \
      "$release_root/scripts/verify-cargo-path-patch-lock.py" \
      "${fips_patch_packages[@]}"
  )" || return 1
  IFS=$'\t' read -r \
    root_lock_sha root_realized_lock_sha \
    linux_lock_sha linux_realized_lock_sha <<<"$lock_evidence"
  target="$(jq -er '.target' "$receipt")" || return 1
  rust_toolchain="${NVPN_HOST_LINUX_VM_RUST_TOOLCHAIN:-1.95.0}"
  dockerfile_sha="$(
    shasum -a 256 "$release_root/Dockerfile.linux-vm-gate" | awk '{print $1}'
  )" || return 1
  payload_sha="$(
    shasum -a 256 \
      "$release_root/scripts/build-host-linux-vm-bundle-in-container.sh" \
      | awk '{print $1}'
  )" || return 1
  [[ "$fips_sha" == "$RELEASE_JOIN_FIPS_SHA" \
    && "$fips_tree" == "$RELEASE_JOIN_FIPS_TREE" \
    && "$fips_version" == "$RELEASE_JOIN_FIPS_VERSION" ]] || {
    ubuntu_vm_import_error "host bundle differs from the exact FIPS checkout"
    return 1
  }
  python3 "$release_root/scripts/verify-host-linux-vm-bundle.py" \
    "$bundle" "$receipt" \
    "$app_sha" "$app_tree" "$app_version" \
    "$fips_sha" "$fips_tree" "$fips_version" \
    "$root_lock_sha" "$root_realized_lock_sha" \
    "$linux_lock_sha" "$linux_realized_lock_sha" "$target" \
    "$builder_mode" "$rust_toolchain" "$dockerfile_sha" "$payload_sha" \
    "${fips_patch_packages[@]}" \
    >/dev/null || {
      ubuntu_vm_import_error "host bundle verification failed"
      return 1
    }

  app_hash="$(jq -er '.artifacts.app.sha256' "$receipt")"
  app_size="$(jq -er '.artifacts.app.size' "$receipt")"
  cli_hash="$(jq -er '.artifacts.cli.sha256' "$receipt")"
  cli_size="$(jq -er '.artifacts.cli.size' "$receipt")"
  fixture_hash="$(jq -er '.artifacts.manualJoinFixture.sha256' "$receipt")"
  fixture_size="$(jq -er '.artifacts.manualJoinFixture.size' "$receipt")"
  musl_hash="$(jq -er '.artifacts.muslCli.sha256' "$receipt")"
  musl_size="$(jq -er '.artifacts.muslCli.size' "$receipt")"
  archive_hash="$(jq -er '.artifacts.muslCliArchive.sha256' "$receipt")"
  archive_size="$(jq -er '.artifacts.muslCliArchive.size' "$receipt")"
  deb_hash="$(jq -er '.artifacts.debianPackage.sha256' "$receipt")"
  deb_size="$(jq -er '.artifacts.debianPackage.size' "$receipt")"

  ubuntu_vm_acquire_import_lock || return 1
  ubuntu_vm_recover_stale_imported_release_bundle || {
    ubuntu_vm_release_import_lock || true
    ubuntu_vm_import_error "stale exact-package recovery failed"
    return 1
  }
  ubuntu_vm_import_ssh_command
  remote_dir="$(
    "${NVPN_UBUNTU_IMPORT_SSH[@]}" bash -s <<'GUEST'
set -euo pipefail
remote_dir="$(mktemp -d /tmp/nvpn-linux-vm-release.XXXXXX)"
chmod 0700 "$remote_dir"
phase_temp="$(mktemp "$remote_dir/.nvpn-deb-phase.XXXXXX")"
printf 'copying\n' >"$phase_temp"
chmod 0400 "$phase_temp"
mv "$phase_temp" "$remote_dir/.nvpn-deb-installed"
printf '%s\n' "$remote_dir"
GUEST
  )" || {
    ubuntu_vm_import_error "could not create the unique VM import directory"
    return 1
  }
  case "$remote_dir" in
    /tmp/nvpn-linux-vm-release.*) ;;
    *)
      ubuntu_vm_import_error "VM returned an unsafe import directory"
      return 1
      ;;
  esac
  NVPN_UBUNTU_IMPORTED_DIR="$remote_dir"

  ubuntu_vm_import_scp_command
  "${NVPN_UBUNTU_IMPORT_SCP[@]}" \
    "$bundle/desktop_manual_join_e2e_fixture" \
    "$SSH_HOST:$remote_dir/desktop_manual_join_e2e_fixture.copy" || return 1
  "${NVPN_UBUNTU_IMPORT_SCP[@]}" \
    "$bundle/nvpn-x86_64-unknown-linux-musl" \
    "$SSH_HOST:$remote_dir/nvpn-x86_64-unknown-linux-musl.copy" || return 1
  "${NVPN_UBUNTU_IMPORT_SCP[@]}" \
    "$bundle/nvpn-x86_64-unknown-linux-musl.tar.gz" \
    "$SSH_HOST:$remote_dir/nvpn-x86_64-unknown-linux-musl.tar.gz.copy" \
    || return 1
  "${NVPN_UBUNTU_IMPORT_SCP[@]}" \
    "$bundle/nostr-vpn.deb" \
    "$SSH_HOST:$remote_dir/nostr-vpn.deb.copy" || return 1
  "${NVPN_UBUNTU_IMPORT_SCP[@]}" \
    "$receipt" \
    "$SSH_HOST:$remote_dir/receipt.json.copy" || return 1

  if ! "${NVPN_UBUNTU_IMPORT_SSH[@]}" bash -s -- \
    "$remote_dir" "$GUEST_REPO" \
    "$app_sha" "$app_tree" "$app_version" \
    "$fips_sha" "$fips_tree" "$fips_version" \
    "$root_lock_sha" "$root_realized_lock_sha" \
    "$linux_lock_sha" "$linux_realized_lock_sha" "$target" \
    "${fips_patch_packages[@]}" \
    "$app_hash" "$app_size" \
    "$cli_hash" "$cli_size" \
    "$fixture_hash" "$fixture_size" \
    "$musl_hash" "$musl_size" \
    "$archive_hash" "$archive_size" \
    "$deb_hash" "$deb_size" \
    "$builder_mode" "$dockerfile_sha" "$payload_sha" \
    "$harness_sha" "$harness_tree" <<'GUEST'
set -euo pipefail
remote_dir="$1"
guest_repo="$2"
app_sha="$3"
app_tree="$4"
app_version="$5"
fips_sha="$6"
fips_tree="$7"
fips_version="$8"
root_lock_sha="$9"
root_realized_lock_sha="${10}"
linux_lock_sha="${11}"
linux_realized_lock_sha="${12}"
target="${13}"
fips_core_patch_spec="${14}"
fips_endpoint_patch_spec="${15}"
fips_identity_patch_spec="${16}"
app_hash="${17}"
app_size="${18}"
cli_hash="${19}"
cli_size="${20}"
fixture_hash="${21}"
fixture_size="${22}"
musl_hash="${23}"
musl_size="${24}"
archive_hash="${25}"
archive_size="${26}"
deb_hash="${27}"
deb_size="${28}"
builder_mode="${29}"
dockerfile_sha="${30}"
payload_sha="${31}"
harness_sha="${32}"
harness_tree="${33}"
write_import_phase() {
  local phase="$1"
  local phase_temp
  phase_temp="$(mktemp "$remote_dir/.nvpn-deb-phase.XXXXXX")"
  printf '%s\n' "$phase" >"$phase_temp"
  chmod 0400 "$phase_temp"
  mv "$phase_temp" "$remote_dir/.nvpn-deb-installed"
}
[[ "$fips_core_patch_spec" == nvpn-fips-core=* ]]
[[ "$fips_endpoint_patch_spec" == nvpn-fips-endpoint=* ]]
[[ "$fips_identity_patch_spec" == nvpn-fips-identity=* ]]
fips_core_patch_version="${fips_core_patch_spec#*=}"
fips_endpoint_patch_version="${fips_endpoint_patch_spec#*=}"
fips_identity_patch_version="${fips_identity_patch_spec#*=}"
case "$remote_dir" in
  /tmp/nvpn-linux-vm-release.*) ;;
  *) exit 2 ;;
esac
[[ -d "$remote_dir" && -O "$remote_dir" && ! -L "$remote_dir" ]]
chmod 0700 "$remote_dir"
[[ "$(git -C "$guest_repo" rev-parse HEAD)" == "$harness_sha" ]]
[[ "$(git -C "$guest_repo" rev-parse 'HEAD^{tree}')" == "$harness_tree" ]]
[[ -z "$(git -C "$guest_repo" status --porcelain --untracked-files=all)" ]]
[[ "$(sha256sum "$guest_repo/Cargo.lock" | awk '{ print $1 }')" == "$root_lock_sha" ]]
[[ "$(sha256sum "$guest_repo/linux/Cargo.lock" | awk '{ print $1 }')" == "$linux_lock_sha" ]]
for artifact in \
  desktop_manual_join_e2e_fixture \
  nvpn-x86_64-unknown-linux-musl
do
  [[ -f "$remote_dir/$artifact.copy" && ! -L "$remote_dir/$artifact.copy" ]]
  chmod 0500 "$remote_dir/$artifact.copy"
  file "$remote_dir/$artifact.copy" | grep -Eq 'ELF 64-bit.*x86-64'
done
for artifact in nostr-vpn.deb nvpn-x86_64-unknown-linux-musl.tar.gz; do
  [[ -f "$remote_dir/$artifact.copy" && ! -L "$remote_dir/$artifact.copy" ]]
  chmod 0400 "$remote_dir/$artifact.copy"
done
chmod 0400 "$remote_dir/receipt.json.copy"
[[ "$(sha256sum "$remote_dir/desktop_manual_join_e2e_fixture.copy" | awk '{ print $1 }')" == "$fixture_hash" ]]
[[ "$(stat -c '%s' "$remote_dir/desktop_manual_join_e2e_fixture.copy")" == "$fixture_size" ]]
[[ "$(sha256sum "$remote_dir/nvpn-x86_64-unknown-linux-musl.copy" | awk '{ print $1 }')" == "$musl_hash" ]]
[[ "$(stat -c '%s' "$remote_dir/nvpn-x86_64-unknown-linux-musl.copy")" == "$musl_size" ]]
[[ "$(sha256sum "$remote_dir/nvpn-x86_64-unknown-linux-musl.tar.gz.copy" | awk '{ print $1 }')" == "$archive_hash" ]]
[[ "$(stat -c '%s' "$remote_dir/nvpn-x86_64-unknown-linux-musl.tar.gz.copy")" == "$archive_size" ]]
[[ "$(sha256sum "$remote_dir/nostr-vpn.deb.copy" | awk '{ print $1 }')" == "$deb_hash" ]]
[[ "$(stat -c '%s' "$remote_dir/nostr-vpn.deb.copy")" == "$deb_size" ]]
jq -e \
  --arg app_sha "$app_sha" \
  --arg app_tree "$app_tree" \
  --arg app_version "$app_version" \
  --arg fips_sha "$fips_sha" \
  --arg fips_tree "$fips_tree" \
  --arg fips_version "$fips_version" \
  --arg root_lock_sha "$root_lock_sha" \
  --arg root_realized_lock_sha "$root_realized_lock_sha" \
  --arg linux_lock_sha "$linux_lock_sha" \
  --arg linux_realized_lock_sha "$linux_realized_lock_sha" \
  --arg fips_core_patch_version "$fips_core_patch_version" \
  --arg fips_endpoint_patch_version "$fips_endpoint_patch_version" \
  --arg fips_identity_patch_version "$fips_identity_patch_version" \
  --arg target "$target" \
  --arg builder_mode "$builder_mode" \
  --arg dockerfile_sha "$dockerfile_sha" \
  --arg payload_sha "$payload_sha" \
  --arg app_hash "$app_hash" \
  --argjson app_size "$app_size" \
  --arg cli_hash "$cli_hash" \
  --argjson cli_size "$cli_size" \
  --arg fixture_hash "$fixture_hash" \
  --argjson fixture_size "$fixture_size" \
  --arg musl_hash "$musl_hash" \
  --argjson musl_size "$musl_size" \
  --arg archive_hash "$archive_hash" \
  --argjson archive_size "$archive_size" \
  --arg deb_hash "$deb_hash" \
  --argjson deb_size "$deb_size" '
    .schema == 2
    and .builderMode == $builder_mode
    and (
      (
        $builder_mode == "local-docker"
        and .builtOnHostMac == true
        and .builtOnRemoteVm == false
        and .builderHostOs == "Darwin"
        and .builderHostArchitecture == "x86_64"
      )
      or (
        $builder_mode == "remote-native"
        and .builtOnHostMac == false
        and .builtOnRemoteVm == true
        and .builderHostOs == "Linux"
        and .builderHostArchitecture == "x86_64"
      )
    )
    and (.containerImageId | test("^sha256:[0-9a-f]{64}$"))
    and .dockerfileSha256 == $dockerfile_sha
    and .containerPayloadSha256 == $payload_sha
    and .appGitSha == $app_sha
    and .appGitTree == $app_tree
    and .appVersion == $app_version
    and .fipsGitSha == $fips_sha
    and .fipsGitTree == $fips_tree
    and .fipsVersion == $fips_version
    and .rootCargoLockSha256 == $root_lock_sha
    and .rootRealizedCargoLockSha256 == $root_realized_lock_sha
    and .linuxCargoLockSha256 == $linux_lock_sha
    and .linuxRealizedCargoLockSha256 == $linux_realized_lock_sha
    and .fipsPatchedLockPackages == {
      "nvpn-fips-core": $fips_core_patch_version,
      "nvpn-fips-endpoint": $fips_endpoint_patch_version,
      "nvpn-fips-identity": $fips_identity_patch_version
    }
    and .target == $target
    and .dockerPlatform == "linux/amd64"
    and .containerBase == "ubuntu:24.04"
    and .artifacts.app.sha256 == $app_hash
    and .artifacts.app.size == $app_size
    and .artifacts.cli.sha256 == $cli_hash
    and .artifacts.cli.size == $cli_size
    and .artifacts.manualJoinFixture.sha256 == $fixture_hash
    and .artifacts.manualJoinFixture.size == $fixture_size
    and .artifacts.muslCli.sha256 == $musl_hash
    and .artifacts.muslCli.size == $musl_size
    and .artifacts.muslCliArchive.sha256 == $archive_hash
    and .artifacts.muslCliArchive.size == $archive_size
    and .artifacts.debianPackage.sha256 == $deb_hash
    and .artifacts.debianPackage.size == $deb_size
  ' "$remote_dir/receipt.json.copy" >/dev/null
python3 "$guest_repo/scripts/host_linux_package_content.py" \
  "$guest_repo" \
  "$remote_dir/nostr-vpn.deb.copy" \
  "$remote_dir/nvpn-x86_64-unknown-linux-musl.tar.gz.copy" \
  "$remote_dir/receipt.json.copy" \
  | grep -Fx HOST_LINUX_PACKAGE_CONTENT_VERIFIED >/dev/null
sed -n '1p' "$remote_dir/nostr-vpn.deb.copy" >/dev/null
[[ "$(dpkg-deb -f "$remote_dir/nostr-vpn.deb.copy" Package)" == "nostr-vpn" ]]
[[ "$(dpkg-deb -f "$remote_dir/nostr-vpn.deb.copy" Version)" \
  == "$app_version-1" ]]
[[ "$(dpkg-deb -f "$remote_dir/nostr-vpn.deb.copy" Architecture)" == "amd64" ]]
package_root="$remote_dir/package-root"
mkdir -m 0700 "$package_root"
dpkg-deb -x "$remote_dir/nostr-vpn.deb.copy" "$package_root"
[[ "$(sha256sum "$package_root/usr/bin/nostr-vpn" | awk '{ print $1 }')" == "$app_hash" ]]
[[ "$(sha256sum "$package_root/usr/bin/nvpn" | awk '{ print $1 }')" == "$cli_hash" ]]
[[ "$(stat -c '%a' "$package_root/usr/bin/nostr-vpn")" == "755" ]]
[[ "$(stat -c '%a' "$package_root/usr/bin/nvpn")" == "755" ]]
[[ -f "$package_root/usr/share/applications/nostr-vpn.desktop" ]]
find "$package_root/usr/share/icons/hicolor" -type f \
  -name nostr-vpn.png -print -quit | grep -q .

archive_root="$remote_dir/archive-root"
mkdir -m 0700 "$archive_root"
tar -xzf "$remote_dir/nvpn-x86_64-unknown-linux-musl.tar.gz.copy" \
  -C "$archive_root"
[[ "$(find "$archive_root" -type f | wc -l)" == "3" ]]
[[ "$(sha256sum "$archive_root/nvpn/nvpn" | awk '{ print $1 }')" == "$musl_hash" ]]
chmod 0500 "$archive_root/nvpn/nvpn"
[[ "$("$archive_root/nvpn/nvpn" --version)" == "nvpn $app_version" ]]
"$archive_root/nvpn/nvpn" version --verbose \
  | grep -Fq "(rev ${fips_sha:0:10})"
rm -rf "$archive_root"

pre_package_status="$(
  dpkg-query -W -f='${db:Status-Status}' nostr-vpn 2>/dev/null || true
)"
if [[ -n "$pre_package_status" ]]; then
  echo "The isolated Ubuntu gate has existing nostr-vpn package state: $pre_package_status" >&2
  exit 2
fi

# Preserve unmanaged/orphaned files at every path the package will own. The
# release VM has historically accumulated old package list files and binaries;
# an exact-package gate must not silently erase that pre-gate state.
preexisting_root="$remote_dir/preexisting-root"
preexisting_info="$remote_dir/preexisting-dpkg-info"
preexisting_paths="$remote_dir/preexisting-paths.txt"
preexisting_manifest="$remote_dir/preexisting-manifest.txt"
mkdir -m 0700 "$preexisting_root" "$preexisting_info"
: >"$preexisting_paths"
while IFS= read -r -d '' candidate; do
  relative="${candidate#"$package_root"}"
  [[ "$relative" == /* && "$relative" != "/" ]] || exit 2
  if [[ -e "$relative" || -L "$relative" ]]; then
    printf '%s\n' "$relative" >>"$preexisting_paths"
    sudo -n cp -a --parents -- "$relative" "$preexisting_root"
  fi
done < <(find "$package_root" -mindepth 1 \( -type f -o -type l \) -print0)
while IFS= read -r info; do
  [[ -f "$info" || -L "$info" ]] || continue
  sudo -n cp -a -- "$info" "$preexisting_info/"
done < <(find /var/lib/dpkg/info -maxdepth 1 \
  \( -name 'nostr-vpn.*' -o -name 'nostr-vpn:*.*' \) -print)
while IFS= read -r candidate; do
  metadata="$(stat -c '%F|%a|%u|%g|%s' "$candidate")"
  if [[ -L "$candidate" ]]; then
    digest="link:$(readlink "$candidate")"
  else
    digest="sha256:$(sha256sum "$candidate" | awk '{ print $1 }')"
  fi
  printf '%s|%s|%s\n' "$candidate" "$metadata" "$digest"
done <"$preexisting_paths" >"$preexisting_manifest"

mv "$remote_dir/desktop_manual_join_e2e_fixture.copy" \
  "$remote_dir/desktop_manual_join_e2e_fixture"
mv "$remote_dir/nvpn-x86_64-unknown-linux-musl.copy" \
  "$remote_dir/nvpn-x86_64-unknown-linux-musl"
mv "$remote_dir/nvpn-x86_64-unknown-linux-musl.tar.gz.copy" \
  "$remote_dir/nvpn-x86_64-unknown-linux-musl.tar.gz"
mv "$remote_dir/nostr-vpn.deb.copy" "$remote_dir/nostr-vpn.deb"
mv "$remote_dir/receipt.json.copy" "$remote_dir/receipt.json"
python3 - \
  "$remote_dir/debian-package-install.json" \
  "$remote_dir/receipt.json" \
  "$app_sha" "$app_tree" "$fips_sha" "$fips_tree" \
  "$app_version" "$deb_hash" "$deb_size" \
  "$app_hash" "$cli_hash" "$musl_hash" "$archive_hash" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
import tempfile

(
    output_arg,
    bundle_receipt_arg,
    app_sha,
    app_tree,
    fips_sha,
    fips_tree,
    app_version,
    deb_sha,
    deb_size,
    app_hash,
    cli_hash,
    musl_hash,
    archive_hash,
) = sys.argv[1:]
bundle_receipt = pathlib.Path(bundle_receipt_arg)
output = pathlib.Path(output_arg)
bundle_payload = json.loads(bundle_receipt.read_text(encoding="utf-8"))
if bundle_payload.get("schema") != 2:
    raise SystemExit("installed package receipt requires bundle schema 2")
payload = {
    "schema": 2,
    "artifactType": "exact Debian package installed on Ubuntu VM",
    "appGitSha": app_sha,
    "appGitTree": app_tree,
    "fipsGitSha": fips_sha,
    "fipsGitTree": fips_tree,
    "appVersion": app_version,
    "builderMode": bundle_payload["builderMode"],
    "builtOnHostMac": bundle_payload["builtOnHostMac"],
    "builtOnRemoteVm": bundle_payload["builtOnRemoteVm"],
    "builderHostOs": bundle_payload["builderHostOs"],
    "builderHostArchitecture": bundle_payload["builderHostArchitecture"],
    "containerImageId": bundle_payload["containerImageId"],
    "dockerfileSha256": bundle_payload["dockerfileSha256"],
    "containerPayloadSha256": bundle_payload["containerPayloadSha256"],
    "package": "nostr-vpn",
    "packageArchitecture": "amd64",
    "packageInstalledByDpkg": True,
    "installedStatus": "installed",
    "installedAppPath": "/usr/bin/nostr-vpn",
    "installedCliPath": "/usr/bin/nvpn",
    "debSha256": deb_sha,
    "debSize": int(deb_size),
    "installedAppSha256": app_hash,
    "installedCliSha256": cli_hash,
    "muslCliSha256": musl_hash,
    "muslArchiveSha256": archive_hash,
    "bundleReceiptSha256": hashlib.sha256(
        bundle_receipt.read_bytes()
    ).hexdigest(),
    "packagePayloadVerifiedBeforeInstall": True,
    "desktopEntryPresent": True,
    "iconThemeAssetPresent": True,
    "muslArchiveExtractedAndExecuted": True,
}
descriptor, temporary_arg = tempfile.mkstemp(
    prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
)
temporary = pathlib.Path(temporary_arg)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
finally:
    temporary.unlink(missing_ok=True)
PY
write_import_phase installing
"$guest_repo/scripts/ubuntu-vm-serialized-dpkg.sh" \
  install "$remote_dir/nostr-vpn.deb" >/dev/null
[[ "$(dpkg-query -W -f='${db:Status-Status}' nostr-vpn)" == "installed" ]]
[[ "$(sha256sum /usr/bin/nostr-vpn | awk '{ print $1 }')" == "$app_hash" ]]
[[ "$(sha256sum /usr/bin/nvpn | awk '{ print $1 }')" == "$cli_hash" ]]
[[ "$(/usr/bin/nvpn --version)" == "nvpn $app_version" ]]
/usr/bin/nvpn version --verbose | grep -Fq "(rev ${fips_sha:0:10})"
write_import_phase installed
GUEST
  then
    ubuntu_vm_import_error "VM hash/version/source verification failed"
    return 1
  fi

  NVPN_UBUNTU_IMPORTED_APP="/usr/bin/nostr-vpn"
  NVPN_UBUNTU_IMPORTED_CLI="/usr/bin/nvpn"
  NVPN_UBUNTU_IMPORTED_FIXTURE="$remote_dir/desktop_manual_join_e2e_fixture"
  NVPN_UBUNTU_IMPORTED_MUSL_CLI="$remote_dir/nvpn-x86_64-unknown-linux-musl"
  NVPN_UBUNTU_IMPORTED_MUSL_ARCHIVE="$remote_dir/nvpn-x86_64-unknown-linux-musl.tar.gz"
  NVPN_UBUNTU_IMPORTED_DEB="$remote_dir/nostr-vpn.deb"
  NVPN_UBUNTU_IMPORTED_RECEIPT="$remote_dir/receipt.json"
  NVPN_UBUNTU_IMPORTED_PACKAGE_RECEIPT="$remote_dir/debian-package-install.json"
  NVPN_UBUNTU_IMPORTED=1
  evidence_dir="${NVPN_UBUNTU_IMPORT_EVIDENCE_DIR:-$ROOT/artifacts/ubuntu-vm-import}"
  mkdir -p "$evidence_dir"
  cp "$receipt" "$evidence_dir/host-bundle-receipt.json"
  "${NVPN_UBUNTU_IMPORT_SCP[@]}" \
    "$SSH_HOST:$remote_dir/debian-package-install.json" \
    "$evidence_dir/debian-package-install.json"
  {
    printf 'builderMode=%s\n' "$(jq -er '.builderMode' "$receipt")"
    printf 'builtOnHostMac=%s\n' "$(jq -er '.builtOnHostMac' "$receipt")"
    printf 'builtOnRemoteVm=%s\n' "$(jq -er '.builtOnRemoteVm' "$receipt")"
    printf 'builderHostOs=%s\n' "$(jq -er '.builderHostOs' "$receipt")"
    printf 'builderHostArchitecture=%s\n' \
      "$(jq -er '.builderHostArchitecture' "$receipt")"
    printf 'appGitSha=%s\n' "$app_sha"
    printf 'appGitTree=%s\n' "$app_tree"
    printf 'fipsGitSha=%s\n' "$fips_sha"
    printf 'fipsGitTree=%s\n' "$fips_tree"
    printf 'harnessGitSha=%s\n' "$harness_sha"
    printf 'harnessGitTree=%s\n' "$harness_tree"
    printf 'rootCargoLockSha256=%s\n' "$root_lock_sha"
    printf 'rootRealizedCargoLockSha256=%s\n' "$root_realized_lock_sha"
    printf 'linuxCargoLockSha256=%s\n' "$linux_lock_sha"
    printf 'linuxRealizedCargoLockSha256=%s\n' "$linux_realized_lock_sha"
    printf 'fipsPatchedLockPackages=%s,%s,%s\n' \
      "${fips_patch_packages[@]}"
    printf 'target=%s\n' "$target"
    printf 'artifactProductSourceVerified=true\n'
    printf 'remoteHarnessSourceVerified=true\n'
    printf 'remoteArtifactHashesVerified=true\n'
    printf 'remoteArtifactSizesVerified=true\n'
    printf 'remoteArtifactVersionsVerified=true\n'
    printf 'exactDebianPackageInstalled=true\n'
    printf 'installedAppPath=/usr/bin/nostr-vpn\n'
    printf 'installedCliPath=/usr/bin/nvpn\n'
    printf 'muslArchiveExtractedAndExecuted=true\n'
  } >"$evidence_dir/import-receipt.txt"
}

ubuntu_vm_cleanup_imported_release_bundle() {
  local remote_dir="${NVPN_UBUNTU_IMPORTED_DIR:-}"
  local cleanup_status=0
  if [[ -z "$remote_dir" ]]; then
    ubuntu_vm_release_import_lock
    return $?
  fi
  case "$remote_dir" in
    /tmp/nvpn-linux-vm-release.*) ;;
    *)
      ubuntu_vm_import_error "refusing unsafe VM import cleanup path"
      ubuntu_vm_release_import_lock || true
      return 1
      ;;
  esac
  if [[ -z "$NVPN_UBUNTU_IMPORT_LOCK_PID" ]] \
    || ! ubuntu_vm_import_lock_holder_alive "$NVPN_UBUNTU_IMPORT_LOCK_PID"
  then
    ubuntu_vm_import_error \
      "refusing imported release cleanup after losing its lifecycle lock"
    ubuntu_vm_release_import_lock || true
    return 1
  fi
  ubuntu_vm_import_ssh_command
  local cleanup_script="$GUEST_REPO/scripts/ubuntu-vm-exact-deb-cleanup.sh"
  "${NVPN_UBUNTU_IMPORT_SSH[@]}" \
    bash "$cleanup_script" "$remote_dir" || {
    ubuntu_vm_import_error \
      "exact Debian package cleanup failed; preserving $remote_dir for repair"
    cleanup_status=1
  }
  if ((cleanup_status == 0)); then
    if ! "${NVPN_UBUNTU_IMPORT_SSH[@]}" \
      bash -s -- "$remote_dir" <<'GUEST'
set -euo pipefail
remote_dir="$1"
case "$remote_dir" in
  /tmp/nvpn-linux-vm-release.*) ;;
  *) exit 2 ;;
esac
find "$remote_dir" -xdev -depth -mindepth 1 -delete
rmdir "$remote_dir"
test ! -e "$remote_dir"
GUEST
    then
      cleanup_status=1
    fi
  fi
  if ((cleanup_status == 0)); then
    local evidence_dir="${NVPN_UBUNTU_IMPORT_EVIDENCE_DIR:-$ROOT/artifacts/ubuntu-vm-import}"
    mkdir -p "$evidence_dir"
    printf 'remoteArtifactRemoved=true\n' >"$evidence_dir/cleanup-audit.txt"
  fi
  NVPN_UBUNTU_IMPORTED_DIR=""
  NVPN_UBUNTU_IMPORTED_APP=""
  NVPN_UBUNTU_IMPORTED_CLI=""
  NVPN_UBUNTU_IMPORTED_FIXTURE=""
  NVPN_UBUNTU_IMPORTED_MUSL_CLI=""
  NVPN_UBUNTU_IMPORTED_MUSL_ARCHIVE=""
  NVPN_UBUNTU_IMPORTED_DEB=""
  NVPN_UBUNTU_IMPORTED_RECEIPT=""
  NVPN_UBUNTU_IMPORTED_PACKAGE_RECEIPT=""
  NVPN_UBUNTU_IMPORTED=0
  ubuntu_vm_release_import_lock || cleanup_status=1
  return "$cleanup_status"
}
