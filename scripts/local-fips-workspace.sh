#!/usr/bin/env bash

nvpn_local_fips_process_start() {
  ps -p "$1" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

nvpn_local_fips_lock_mtime() {
  stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null
}

nvpn_local_fips_file_sha256() {
  shasum -a 256 "$1" | awk '{print tolower($1)}'
}

nvpn_restore_local_fips_lock_snapshot() {
  local snapshot="$1" destination="$2" temporary
  temporary="$(mktemp "${destination}.nvpn-restore.XXXXXX")" || return 1
  if ! cp -p "$snapshot" "$temporary" || ! mv -f "$temporary" "$destination"; then
    rm -f "$temporary"
    return 1
  fi
}

nvpn_local_fips_remove_lock_atomically() {
  local lock="$1" label="$2" expected_token="${3:-}" observed_token=""
  local retired="${lock}.${label}.$$.$RANDOM"
  if [[ ! -d "$lock" ]]; then
    echo "local-FIPS workspace lock disappeared before atomic removal" >&2
    return 1
  fi
  if [[ -n "$expected_token" ]] \
    && { [[ ! -f "$lock/token" ]] \
      || ! IFS= read -r observed_token <"$lock/token" \
      || [[ "$observed_token" != "$expected_token" ]]; }
  then
    echo "local-FIPS workspace lock ownership changed before atomic removal" >&2
    return 1
  fi
  if [[ -e "$retired" ]] || ! mv "$lock" "$retired"; then
    echo "could not atomically retire local-FIPS workspace lock" >&2
    return 1
  fi
  if [[ -n "$expected_token" ]]; then
    observed_token=""
    if [[ ! -f "$retired/token" ]] \
      || ! IFS= read -r observed_token <"$retired/token" \
      || [[ "$observed_token" != "$expected_token" ]]
    then
      echo "local-FIPS workspace lock ownership changed during atomic removal" >&2
      return 2
    fi
  fi
  if ! rm -rf "$retired" || [[ -e "$retired" ]]; then
    echo "could not remove retired local-FIPS workspace lock" >&2
    return 2
  fi
}

nvpn_local_fips_lock_path() {
  local root="$1" lock_root key
  if ! root="$(cd "$root" && pwd -P)"; then
    echo "could not resolve local-FIPS workspace root" >&2
    return 1
  fi
  lock_root="${NVPN_LOCAL_FIPS_LOCK_ROOT:-${TMPDIR:-/tmp}}"
  if ! mkdir -p "$lock_root"; then
    echo "could not create local-FIPS lock root: $lock_root" >&2
    return 1
  fi
  if ! key="$(
    printf '%s' "$root" \
      | shasum -a 256 \
      | awk '{print substr($1, 1, 24)}'
  )" || [[ ! "$key" =~ ^[0-9a-f]{24}$ ]]; then
    echo "could not derive local-FIPS workspace lock path" >&2
    return 1
  fi
  printf '%s/nvpn-local-fips-%s.lock\n' "${lock_root%/}" "$key"
}

nvpn_local_fips_lock_is_stale() {
  local lock="$1" pid started current_started now mtime
  if [[ ! -f "$lock/ready" ]]; then
    now="$(date +%s)"
    mtime="$(nvpn_local_fips_lock_mtime "$lock" || true)"
    [[ "$mtime" =~ ^[0-9]+$ ]] && (( now - mtime >= 10 ))
    return
  fi
  [[ -f "$lock/pid" && -f "$lock/process-start" ]] || return 0
  pid="$(<"$lock/pid")"
  started="$(<"$lock/process-start")"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  [[ "$started" != "pid-only" ]] || return 1
  current_started="$(nvpn_local_fips_process_start "$pid")"
  [[ -n "$current_started" && "$current_started" != "$started" ]]
}

nvpn_local_fips_recover_stale_lock() {
  local lock="$1" root="$2" recorded_root=""
  mkdir "$lock/recovery" 2>/dev/null || return 1
  if ! nvpn_local_fips_lock_is_stale "$lock"; then
    rmdir "$lock/recovery" 2>/dev/null || true
    return 1
  fi
  if [[ -f "$lock/root" ]]; then
    recorded_root="$(<"$lock/root")"
  fi
  if [[ -n "$recorded_root" && "$recorded_root" != "$root" ]]; then
    echo "local FIPS lock belongs to a different checkout: $lock" >&2
    rmdir "$lock/recovery" 2>/dev/null || true
    return 1
  fi
  if [[ -f "$lock/ready" && ! -f "$lock/Cargo.lock.snapshot" ]]; then
    echo "stale local-FIPS owner has no recoverable Cargo.lock snapshot" >&2
    rmdir "$lock/recovery" 2>/dev/null || true
    return 1
  fi
  if [[ -f "$lock/Cargo.lock.snapshot" ]]; then
    if ! nvpn_restore_local_fips_lock_snapshot \
      "$lock/Cargo.lock.snapshot" "$root/Cargo.lock"
    then
      echo "could not restore Cargo.lock from stale local-FIPS owner" >&2
      rmdir "$lock/recovery" 2>/dev/null || true
      return 1
    fi
  fi
  if ! nvpn_local_fips_remove_lock_atomically "$lock" recovery; then
    echo "could not remove stale local-FIPS workspace lock" >&2
    return 1
  fi
  printf 'recovered stale local-FIPS workspace owner\n'
}

nvpn_acquire_local_fips_lock() {
  local root="$1" timeout="${NVPN_LOCAL_FIPS_LOCK_TIMEOUT_SECS:-3600}"
  local lock deadline token started release_manifest_sha
  [[ "$timeout" =~ ^[1-9][0-9]*$ ]] || {
    echo "NVPN_LOCAL_FIPS_LOCK_TIMEOUT_SECS must be a positive integer" >&2
    return 1
  }
  if ! root="$(cd "$root" && pwd -P)"; then
    echo "could not resolve local-FIPS workspace root" >&2
    return 1
  fi
  lock="$(nvpn_local_fips_lock_path "$root")" || return 1
  deadline=$((SECONDS + timeout))
  while ! mkdir "$lock" 2>/dev/null; do
    if nvpn_local_fips_lock_is_stale "$lock" \
      && nvpn_local_fips_recover_stale_lock "$lock" "$root"
    then
      continue
    fi
    if (( SECONDS >= deadline )); then
      echo "timed out waiting for local-FIPS workspace owner: $lock" >&2
      return 1
    fi
    sleep 0.1
  done

  token="$$-$RANDOM-$(date +%s)"
  started="$(nvpn_local_fips_process_start "$$")"
  [[ -n "$started" ]] || started="pid-only"
  if ! printf '%s\n' "$$" >"$lock/pid" \
    || ! printf '%s\n' "$started" >"$lock/process-start" \
    || ! printf '%s\n' "$root" >"$lock/root" \
    || ! printf '%s\n' "$token" >"$lock/token" \
    || ! cp -p "$root/Cargo.lock" "$lock/Cargo.lock.snapshot"
  then
    if ! nvpn_local_fips_remove_lock_atomically "$lock" incomplete; then
      echo "could not remove incomplete local-FIPS workspace lock" >&2
    fi
    echo "could not initialize local-FIPS workspace lock" >&2
    return 1
  fi
  if ! release_manifest_sha="$(
    nvpn_local_fips_file_sha256 "$root/Cargo.toml"
  )" || [[ ! "$release_manifest_sha" =~ ^[0-9a-f]{64}$ ]] \
    || ! printf '%s\n' "$release_manifest_sha" >"$lock/Cargo.toml.sha256" \
    || ! : >"$lock/ready"
  then
    if ! nvpn_local_fips_remove_lock_atomically "$lock" incomplete; then
      echo "could not remove incomplete local-FIPS workspace lock" >&2
    fi
    echo "could not finalize local-FIPS workspace lock" >&2
    return 1
  fi

  NVPN_LOCAL_FIPS_LOCK_DIR="$lock"
  NVPN_LOCAL_FIPS_LOCK_TOKEN="$token"
  NVPN_LOCAL_FIPS_LOCK_SNAPSHOT="$lock/Cargo.lock.snapshot"
  export NVPN_LOCAL_FIPS_LOCK_DIR
  export NVPN_LOCAL_FIPS_LOCK_TOKEN
  export NVPN_LOCAL_FIPS_LOCK_SNAPSHOT
}

nvpn_restore_local_fips_workspace() {
  local lock="${NVPN_LOCAL_FIPS_LOCK_DIR:-}" token="${NVPN_LOCAL_FIPS_LOCK_TOKEN:-}"
  local root="${NVPN_LOCAL_FIPS_ROOT:-}" owned_token=""
  local cleanup_failed=0 expected_manifest_sha="" observed_manifest_sha=""
  local lock_removal_status=-1
  if [[ -n "$lock" ]]; then
    if [[ ! -d "$lock" ]]; then
      echo "owned local-FIPS workspace lock disappeared before cleanup" >&2
      return 1
    fi
    if [[ -z "$token" || ! -f "$lock/token" ]] \
      || ! IFS= read -r owned_token <"$lock/token" \
      || [[ "$owned_token" != "$token" ]]
    then
      echo "local-FIPS workspace lock ownership changed before cleanup" >&2
      return 1
    fi
    if [[ -z "$root" ]]; then
      echo "local-FIPS workspace root is missing during cleanup" >&2
      return 1
    fi
  fi
  if [[ -n "${NVPN_LOCAL_FIPS_LOCK_SNAPSHOT:-}" \
        && -f "$NVPN_LOCAL_FIPS_LOCK_SNAPSHOT" ]]; then
    if [[ ! -f "$root/Cargo.lock" ]] \
      || ! cmp -s "$NVPN_LOCAL_FIPS_LOCK_SNAPSHOT" "$root/Cargo.lock"
    then
      if nvpn_restore_local_fips_lock_snapshot \
        "$NVPN_LOCAL_FIPS_LOCK_SNAPSHOT" "$root/Cargo.lock"
      then
        printf 'restored Cargo.lock after local-FIPS cargo run\n'
      else
        echo "could not restore Cargo.lock after local-FIPS cargo run" >&2
        cleanup_failed=1
      fi
    fi
  elif [[ -n "$lock" ]]; then
    echo "Cargo.lock snapshot is missing after local-FIPS build" >&2
    cleanup_failed=1
  fi
  if [[ -n "$lock" && -f "$lock/Cargo.toml.sha256" \
    && -f "$root/Cargo.toml" ]]
  then
    expected_manifest_sha="$(<"$lock/Cargo.toml.sha256")"
    observed_manifest_sha="$(
      nvpn_local_fips_file_sha256 "$root/Cargo.toml"
    )"
    if [[ "$observed_manifest_sha" != "$expected_manifest_sha" ]]; then
      echo "Cargo.toml changed during the local-FIPS build" >&2
      cleanup_failed=1
    fi
  elif [[ -n "$lock" ]]; then
    echo "Cargo.toml verification data is missing after local-FIPS build" >&2
    cleanup_failed=1
  fi
  if [[ -n "$lock" && "$cleanup_failed" -eq 0 ]]; then
    owned_token=""
    if [[ ! -d "$lock" || ! -f "$lock/token" ]] \
      || ! IFS= read -r owned_token <"$lock/token" \
      || [[ "$owned_token" != "$token" ]]
    then
      echo "local-FIPS workspace lock ownership changed during cleanup" >&2
      cleanup_failed=1
    else
      lock_removal_status=0
      nvpn_local_fips_remove_lock_atomically "$lock" release "$token" \
        || lock_removal_status=$?
      if [[ "$lock_removal_status" -ne 0 ]]; then
        cleanup_failed=1
      fi
    fi
  fi
  if [[ "$lock_removal_status" -eq 0 || "$lock_removal_status" -eq 2 ]] \
    || { [[ -z "$lock" ]] && [[ "$cleanup_failed" -eq 0 ]]; }
  then
    NVPN_LOCAL_FIPS_LOCK_DIR=""
    NVPN_LOCAL_FIPS_LOCK_TOKEN=""
    NVPN_LOCAL_FIPS_LOCK_SNAPSHOT=""
  fi
  return "$cleanup_failed"
}

nvpn_validate_preconfigured_local_fips_session() {
  local root="$1" fips_path="$2"
  local manifest_sha lock_sha fips_path_sha fips_head fips_tree session_sha
  for session_sha in \
    NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256 \
    NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256 \
    NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256
  do
    [[ "${!session_sha:-}" =~ ^[0-9a-f]{64}$ ]] || {
      echo "preconfigured local-FIPS session is missing $session_sha" >&2
      return 1
    }
  done
  [[ "${NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD:-}" =~ ^[0-9a-f]{40}$ \
    && "${NVPN_LOCAL_FIPS_SESSION_FIPS_TREE:-}" =~ ^[0-9a-f]{40}$ ]] || {
    echo "preconfigured local-FIPS session has no exact FIPS revision" >&2
    return 1
  }
  manifest_sha="$(nvpn_local_fips_file_sha256 "$root/Cargo.toml")"
  lock_sha="$(nvpn_local_fips_file_sha256 "$root/Cargo.lock")"
  fips_path="$(cd "$fips_path" && pwd -P)"
  fips_path_sha="$(
    printf '%s' "$fips_path" | shasum -a 256 | awk '{print tolower($1)}'
  )"
  fips_head="$(git -C "$fips_path" rev-parse HEAD)"
  fips_tree="$(git -C "$fips_path" rev-parse 'HEAD^{tree}')"
  [[ "$manifest_sha" == "$NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256" \
    && "$lock_sha" == "$NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256" \
    && "$fips_path_sha" == "$NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256" \
    && "$fips_head" == "$NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD" \
    && "$fips_tree" == "$NVPN_LOCAL_FIPS_SESSION_FIPS_TREE" \
    && -z "$(git -C "$fips_path" status --porcelain --untracked-files=all)" ]] \
    || {
      echo "preconfigured local-FIPS session no longer matches its exact inputs" >&2
      return 1
    }
}

nvpn_local_fips_exit_cleanup() {
  local status="$?" cleanup_failed=0
  trap - EXIT
  nvpn_restore_local_fips_workspace || cleanup_failed=1
  if [[ "$status" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    status=1
  fi
  exit "$status"
}

nvpn_install_local_fips_cargo_wrapper() {
  local fips_path="$1" real_cargo wrapper wrapper_script
  if ! real_cargo="$(command -v cargo)" || [[ -z "$real_cargo" ]]; then
    echo "could not find cargo for local-FIPS wrapper" >&2
    return 1
  fi
  [[ -n "${NVPN_LOCAL_FIPS_LOCK_DIR:-}" ]] || {
    echo "local-FIPS wrapper requires an owned workspace lock" >&2
    return 1
  }
  wrapper="$NVPN_LOCAL_FIPS_LOCK_DIR/cargo-wrapper"
  if ! mkdir -p "$wrapper"; then
    echo "could not create local-FIPS cargo wrapper directory" >&2
    return 1
  fi
  wrapper_script="$wrapper/.cargo.$$.$RANDOM"
  if ! {
    printf '#!/usr/bin/env bash\n' \
      && printf 'exec %q' "$real_cargo" \
      && printf ' --config %q' \
      "patch.crates-io.nvpn-fips-core.path=\"$fips_path/crates/fips-core\"" \
      "patch.crates-io.nvpn-fips-endpoint.path=\"$fips_path/crates/fips-endpoint\"" \
      "patch.crates-io.nvpn-fips-identity.path=\"$fips_path/crates/fips-identity\"" \
      && printf ' \"$@\"\n'
  } >"$wrapper_script"; then
    rm -f "$wrapper_script"
    echo "could not write local-FIPS cargo wrapper" >&2
    return 1
  fi
  if ! chmod 700 "$wrapper_script" \
    || ! mv -f "$wrapper_script" "$wrapper/cargo"
  then
    rm -f "$wrapper_script"
    echo "could not install local-FIPS cargo wrapper" >&2
    return 1
  fi
  export PATH="$wrapper:$PATH"
}

nvpn_validated_fips_repo_path() {
  local fips_path="${NVPN_FIPS_REPO_PATH:-}"
  [[ -n "$fips_path" ]] || return 1
  if [[ ! -d "$fips_path/crates/fips-core" \
        || ! -d "$fips_path/crates/fips-endpoint" \
        || ! -d "$fips_path/crates/fips-identity" ]]; then
    echo "NVPN_FIPS_REPO_PATH must point at a fips checkout with fips-core, fips-endpoint, and fips-identity" >&2
    exit 1
  fi
  printf '%s\n' "$fips_path"
}

nvpn_prepare_local_fips_workspace() {
  [[ -n "${NVPN_FIPS_REPO_PATH:-}" ]] || return 0
  [[ -z "${NVPN_LOCAL_FIPS_PREPARED:-}" ]] || return 0

  NVPN_LOCAL_FIPS_ROOT="$1"
  local fips_path
  fips_path="$(nvpn_validated_fips_repo_path)" || return 1

  if [[ "${NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED:-0}" == "1" ]]; then
    nvpn_validate_preconfigured_local_fips_session \
      "$NVPN_LOCAL_FIPS_ROOT" "$fips_path" || return 1
    NVPN_LOCAL_FIPS_PREPARED=1
    export NVPN_LOCAL_FIPS_PREPARED
    printf 'using preconfigured exact local FIPS checkout\n'
    return 0
  fi
  if [[ -n "$(trap -p EXIT)" ]]; then
    echo "local FIPS workspace refuses to replace an existing EXIT cleanup" >&2
    return 1
  fi
  if ! nvpn_acquire_local_fips_lock "$NVPN_LOCAL_FIPS_ROOT"; then
    return 1
  fi
  if ! trap nvpn_local_fips_exit_cleanup EXIT; then
    nvpn_restore_local_fips_workspace || true
    return 1
  fi
  if ! nvpn_install_local_fips_cargo_wrapper "$fips_path"; then
    if nvpn_restore_local_fips_workspace; then
      trap - EXIT
    else
      echo "could not roll back local-FIPS workspace setup" >&2
    fi
    return 1
  fi

  NVPN_LOCAL_FIPS_PREPARED=1
  export NVPN_LOCAL_FIPS_PREPARED
  export NVPN_LOCAL_FIPS_ROOT
  export NVPN_LOCAL_FIPS_LOCK_SNAPSHOT
  printf 'using exact local FIPS checkout\n'
}

nvpn_verify_local_fips_metadata() {
  local root="$1" receipt="$2"
  [[ -n "${NVPN_FIPS_REPO_PATH:-}" ]] || return 0
  [[ -z "${NVPN_LOCAL_FIPS_METADATA_VERIFIED:-}" ]] || return 0
  local fips_path head tree version metadata metadata_log
  fips_path="$(nvpn_validated_fips_repo_path)"
  head="$(git -C "$fips_path" rev-parse HEAD)"
  tree="$(git -C "$fips_path" rev-parse 'HEAD^{tree}')"
  [[ -z "$(git -C "$fips_path" status --porcelain --untracked-files=all)" ]] || {
    echo "local FIPS linkage refuses a dirty checkout" >&2
    return 1
  }
  if [[ -n "${NVPN_EXPECTED_FIPS_GIT_SHA:-}" \
    && "$NVPN_EXPECTED_FIPS_GIT_SHA" != "$head" ]]
  then
    echo "local FIPS linkage HEAD does not match the required revision" >&2
    return 1
  fi
  version="$(
    awk '
      $0 == "[package]" { package = 1; next }
      package && /^\[/ { exit }
      package && /^version = "/ {
        value = $0
        sub(/^version = "/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
      }
    ' "$fips_path/crates/fips-core/Cargo.toml"
  )"
  [[ -n "$version" ]] || {
    echo "local FIPS linkage could not read the fips-core package version" >&2
    return 1
  }
  if [[ -n "${NVPN_EXPECTED_FIPS_VERSION:-}" \
    && "$NVPN_EXPECTED_FIPS_VERSION" != "$version" ]]
  then
    echo "local FIPS linkage version does not match the required version" >&2
    return 1
  fi
  metadata="$(mktemp "${TMPDIR:-/tmp}/nvpn-fips-metadata.XXXXXX.json")"
  metadata_log="$(mktemp "${TMPDIR:-/tmp}/nvpn-fips-metadata.XXXXXX.log")"
  if ! (cd "$root" && cargo metadata --format-version 1 \
    >"$metadata" 2>"$metadata_log")
  then
    rm -f "$metadata" "$metadata_log"
    echo "Cargo metadata could not resolve the exact local FIPS checkout" >&2
    return 1
  fi
  rm -f "$metadata_log"
  mkdir -p "$(dirname "$receipt")"
  if ! python3 - \
    "$metadata" "$receipt" "$fips_path" "$version" "$head" "$tree" <<'PY'
import json
import hashlib
import os
import sys

metadata_path, receipt_path, checkout, version, head, tree = sys.argv[1:]
payload = json.load(open(metadata_path, encoding="utf-8"))
manifest = os.path.realpath(
    os.path.join(checkout, "crates", "fips-core", "Cargo.toml")
)
matches = [
    package
    for package in payload.get("packages", [])
    if package.get("name") == "nvpn-fips-core"
]
if len(matches) != 1:
    raise SystemExit(f"Cargo metadata resolved {len(matches)} nvpn-fips-core packages")
package = matches[0]
if os.path.realpath(package.get("manifest_path", "")) != manifest:
    raise SystemExit("Cargo metadata did not resolve nvpn-fips-core to the exact checkout")
if package.get("version") != version:
    raise SystemExit("Cargo metadata resolved the wrong nvpn-fips-core version")
if package.get("source") is not None:
    raise SystemExit("Cargo metadata resolved a registry nvpn-fips-core package")
package_id = package.get("id")
nodes = payload.get("resolve", {}).get("nodes", [])
if not any(node.get("id") == package_id for node in nodes):
    raise SystemExit("Cargo dependency graph does not contain exact local nvpn-fips-core")
with open(receipt_path, "w", encoding="utf-8") as output:
    checkout_path = os.path.realpath(checkout)
    json.dump(
        {
            "checkoutHead": head,
            "checkoutPathSha256": hashlib.sha256(
                checkout_path.encode()
            ).hexdigest(),
            "checkoutTree": tree,
            "fipsCoreManifestPathSha256": hashlib.sha256(
                manifest.encode()
            ).hexdigest(),
            "fipsCorePackageIdSha256": hashlib.sha256(
                package_id.encode()
            ).hexdigest(),
            "fipsCoreVersion": version,
            "source": "exact clean local Cargo path dependency",
        },
        output,
        indent=2,
        sort_keys=True,
    )
    output.write("\n")
PY
  then
    rm -f "$metadata"
    return 1
  fi
  rm -f "$metadata"
  NVPN_LOCAL_FIPS_METADATA_VERIFIED=1
  NVPN_VERIFIED_FIPS_HEAD="$head"
  NVPN_VERIFIED_FIPS_TREE="$tree"
  NVPN_VERIFIED_FIPS_VERSION="$version"
}

nvpn_force_rebuild_local_fips_target() {
  local root="$1" target="$2" profile="$3" marker="$4"
  [[ -n "${NVPN_FIPS_REPO_PATH:-}" ]] || return 0
  local key="NVPN_LOCAL_FIPS_CLEANED_${target//-/_}_${profile}"
  [[ -z "${!key:-}" ]] || return 0
  local -a profile_args=()
  [[ "$profile" != "release" ]] || profile_args+=(--release)
  (
    cd "$root"
    cargo clean -p nvpn-fips-core -p nvpn-fips-endpoint -p nvpn-fips-identity \
      --target "$target" "${profile_args[@]}"
  ) >/dev/null
  mkdir -p "$(dirname "$marker")"
  touch "$marker"
  printf -v "$key" 1
}
