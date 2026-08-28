#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MOBILE_IOS_APP_READY=0
MOBILE_ANDROID_APP_READY=0
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/release_common.sh"
source "$ROOT_DIR/scripts/lib-release-gate-timeout.sh"
source "$ROOT_DIR/scripts/lib-release-gate-parallel.sh"
source "$ROOT_DIR/scripts/lib-release-gate-required-modes.sh"
source "$ROOT_DIR/scripts/lib-macos-vm-identity.sh"
source "$ROOT_DIR/scripts/lib-ubuntu-vm-imported-release.sh"
source "$ROOT_DIR/scripts/mobile_env.sh"
load_mobile_env "$ROOT_DIR"
enable_deterministic_build_env "$ROOT_DIR"

export NVPN_IDLE_CPU_GATE="${NVPN_RELEASE_GATE_IDLE_CPU:-${NVPN_IDLE_CPU_GATE:-1}}"
export NVPN_IDLE_CPU_MAX_PERCENT="${NVPN_RELEASE_GATE_IDLE_CPU_MAX_PERCENT:-${NVPN_IDLE_CPU_MAX_PERCENT:-2}}"
export NVPN_LINUX_DAEMON_IDLE_CPU_MAX_PERCENT="${NVPN_LINUX_DAEMON_IDLE_CPU_MAX_PERCENT:-3}"
export NVPN_IDLE_CPU_SAMPLE_SECONDS="${NVPN_RELEASE_GATE_IDLE_CPU_SAMPLE_SECONDS:-${NVPN_IDLE_CPU_SAMPLE_SECONDS:-60}}"
export NVPN_IDLE_CPU_SETTLE_SECONDS="${NVPN_RELEASE_GATE_IDLE_CPU_SETTLE_SECONDS:-${NVPN_IDLE_CPU_SETTLE_SECONDS:-15}}"
# The Android VPN fixture maintains the two production bootstrap adjacencies,
# unlike the foreground/UI idle gates. Keep a separate bound for that active
# encrypted overlay while retaining the packet/TUN correctness probe below.
# The shipped, nondebuggable foreground app has no active overlay work. Keep
# this independent of the background active-VPN allowance above so every exact
# Release candidate proves a full low-idle minute before artifact reuse.
ANDROID_RELEASE_FOREGROUND_IDLE_CPU_MAX_PERCENT="${NVPN_ANDROID_RELEASE_FOREGROUND_IDLE_CPU_MAX_PERCENT:-2}"
ANDROID_RELEASE_FOREGROUND_IDLE_CPU_SAMPLE_SECONDS="${NVPN_ANDROID_RELEASE_FOREGROUND_IDLE_CPU_SAMPLE_SECONDS:-60}"

MACOS_WG_EXIT_TIMEOUT_SECS="${NVPN_RELEASE_GATE_MACOS_WG_EXIT_TIMEOUT_SECS:-300}"
WINDOWS_WG_EXIT_TIMEOUT_SECS="${NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_TIMEOUT_SECS:-1800}"
LINUX_GUI_SMOKE_TIMEOUT_SECS="${NVPN_RELEASE_GATE_LINUX_GUI_SMOKE_TIMEOUT_SECS:-1800}"
MACOS_GUI_SMOKE_TIMEOUT_SECS="${NVPN_RELEASE_GATE_MACOS_GUI_SMOKE_TIMEOUT_SECS:-900}"
MACOS_DAEMON_IDLE_CPU_TIMEOUT_SECS="${NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU_TIMEOUT_SECS:-600}"
WINDOWS_GUI_SMOKE_TIMEOUT_SECS="${NVPN_RELEASE_GATE_WINDOWS_GUI_SMOKE_TIMEOUT_SECS:-1800}"
DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS="${NVPN_RELEASE_GATE_DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS:-1800}"
DESKTOP_SERVICE_TOGGLE_TIMEOUT_SECS="${NVPN_RELEASE_GATE_DESKTOP_SERVICE_TOGGLE_TIMEOUT_SECS:-1800}"
DESKTOP_DNS_UI_TIMEOUT_SECS="${NVPN_RELEASE_GATE_DESKTOP_DNS_UI_TIMEOUT_SECS:-900}"
PAID_EXIT_SELLER_UI_TIMEOUT_SECS="${NVPN_RELEASE_GATE_PAID_EXIT_SELLER_UI_TIMEOUT_SECS:-900}"
DESKTOP_UNDERLAY_NETWORK_CHANGE_TIMEOUT_SECS="${NVPN_RELEASE_GATE_DESKTOP_UNDERLAY_NETWORK_CHANGE_TIMEOUT_SECS:-2400}"
ANDROID_LEGACY_REPLACEMENT_TIMEOUT_SECS="${NVPN_RELEASE_GATE_ANDROID_LEGACY_REPLACEMENT_TIMEOUT_SECS:-600}"
IOS_TUNNEL_IDLE_CPU_TIMEOUT_SECS="${NVPN_RELEASE_GATE_IOS_TUNNEL_IDLE_CPU_TIMEOUT_SECS:-180}"
MOBILE_WG_EXIT_TIMEOUT_SECS="${NVPN_RELEASE_GATE_MOBILE_WG_EXIT_TIMEOUT_SECS:-3600}"
MOBILE_JOIN_E2E_TIMEOUT_SECS="${NVPN_RELEASE_GATE_MOBILE_JOIN_E2E_TIMEOUT_SECS:-1800}"
RELEASE_GATE_TARGET_SECS="${NVPN_RELEASE_GATE_TARGET_SECS:-1800}"

release_cargo_config_args=()
release_cargo_config_backup=""
release_cargo_config_existed=0
release_cargo_config_path="$ROOT_DIR/.cargo/config.toml"
release_cargo_lock_args=(--locked)
release_cargo_lock_backup=""
release_cargo_wrapper_dir=""
release_fips_path=""
release_cargo_lock_original_sha256=""
release_cargo_manifest_original_sha256=""
HOST_LINUX_VM_BUNDLE_PATH_RECEIPT=""
WINDOWS_PLATFORM_PREPARATION_RECEIPT=""
MACOS_PLATFORM_PREPARATION_RECEIPT=""
LINUX_PLATFORM_PREPARATION_RECEIPT=""

write_platform_preparation_receipt() {
  local receipt="$1" platform="$2" temporary app_head app_tree
  [[ -n "$receipt" && -n "$platform" ]] || return 2
  app_head="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  app_tree="$(git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}')"
  assert_release_checkout_state \
    "$ROOT_DIR" "$app_head" "$app_tree" \
    "$platform platform preparation" || return 1
  temporary="${receipt}.tmp.$$"
  (
    umask 077
    printf '%s\t%s\t%s\n' "$platform" "$app_head" "$app_tree" >"$temporary"
  )
  mv -f "$temporary" "$receipt"
}

platform_preparation_receipt_valid() {
  local receipt="$1" expected_platform="$2"
  local platform app_head app_tree extra line_count
  [[ -f "$receipt" && ! -L "$receipt" ]] || return 1
  line_count="$(wc -l <"$receipt" | tr -d '[:space:]')"
  [[ "$line_count" == "1" ]] || return 1
  IFS=$'\t' read -r platform app_head app_tree extra <"$receipt"
  [[ "$platform" == "$expected_platform" \
    && -z "$extra" \
    && "$app_head" == "$(git -C "$ROOT_DIR" rev-parse HEAD)" \
    && "$app_tree" == "$(git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}')" ]]
}

restore_release_cargo_lock() {
  local cleanup_failed=0
  if [[ -n "$release_cargo_manifest_original_sha256" \
    && "$(release_file_sha256 "$ROOT_DIR/Cargo.toml")" \
      != "$release_cargo_manifest_original_sha256" ]]
  then
    echo "Release gate Cargo.toml changed during the local-FIPS session." >&2
    cleanup_failed=1
  fi
  if [[ -n "${NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256:-}" \
    && "$(release_file_sha256 "$ROOT_DIR/Cargo.lock")" \
      != "$NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256" ]]
  then
    echo "Release gate Cargo.lock changed after local-FIPS preparation." >&2
    cleanup_failed=1
  fi
  if [[ -n "$release_cargo_config_backup" ]]; then
    if [[ "$release_cargo_config_existed" == "1" ]]; then
      cp "$release_cargo_config_backup" "$release_cargo_config_path" \
        || cleanup_failed=1
    else
      rm -f "$release_cargo_config_path" || cleanup_failed=1
    fi
    rm -f "$release_cargo_config_backup" || cleanup_failed=1
    release_cargo_config_backup=""
  fi
  if [[ -n "$release_cargo_lock_backup" ]]; then
    cp "$release_cargo_lock_backup" "$ROOT_DIR/Cargo.lock" \
      || cleanup_failed=1
    rm -f "$release_cargo_lock_backup" || cleanup_failed=1
    release_cargo_lock_backup=""
  fi
  if [[ -n "$release_cargo_wrapper_dir" ]]; then
    rm -rf "$release_cargo_wrapper_dir" || cleanup_failed=1
    release_cargo_wrapper_dir=""
  fi
  if [[ -n "$release_cargo_manifest_original_sha256" \
    && "$(release_file_sha256 "$ROOT_DIR/Cargo.toml")" \
      != "$release_cargo_manifest_original_sha256" ]]
  then
    echo "Release gate failed to restore the original Cargo.toml." >&2
    cleanup_failed=1
  fi
  if [[ -n "$release_cargo_lock_original_sha256" \
    && "$(release_file_sha256 "$ROOT_DIR/Cargo.lock")" \
      != "$release_cargo_lock_original_sha256" ]]
  then
    echo "Release gate failed to restore the original Cargo.lock." >&2
    cleanup_failed=1
  fi
  unset NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED
  unset NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256
  unset NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256
  unset NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256
  unset NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD
  unset NVPN_LOCAL_FIPS_SESSION_FIPS_TREE
  return "$cleanup_failed"
}

install_release_cargo_wrapper() {
  if ((${#release_cargo_config_args[@]} == 0)) || [[ -n "$release_cargo_wrapper_dir" ]]; then
    return
  fi

  local real_cargo
  real_cargo="$(command -v cargo)"
  release_cargo_wrapper_dir="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-release-gate-cargo.XXXXXX")"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'if [[ -z "${NVPN_FIPS_REPO_PATH:-}" ]]; then\n'
    printf '  exec %q "$@"\n' "$real_cargo"
    printf 'fi\n'
    printf 'exec %q' "$real_cargo"
    printf ' %q' "${release_cargo_config_args[@]}"
    printf ' "$@"\n'
  } >"$release_cargo_wrapper_dir/cargo"
  chmod +x "$release_cargo_wrapper_dir/cargo"
  export PATH="$release_cargo_wrapper_dir:$PATH"
}

toml_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

install_release_cargo_config() {
  if ((${#release_cargo_config_args[@]} == 0)) || [[ -n "$release_cargo_config_backup" ]]; then
    return
  fi

  mkdir -p "$(dirname "$release_cargo_config_path")"
  release_cargo_config_backup="$(mktemp "${TMPDIR:-/tmp}/nvpn-release-gate-cargo-config.XXXXXX")"
  if [[ -f "$release_cargo_config_path" ]]; then
    release_cargo_config_existed=1
    cp "$release_cargo_config_path" "$release_cargo_config_backup"
  else
    release_cargo_config_existed=0
    : >"$release_cargo_config_backup"
  fi

  cat >"$release_cargo_config_path" <<EOF
[patch.crates-io]
nvpn-fips-core = { path = $(toml_string "$release_fips_path/crates/fips-core") }
nvpn-fips-endpoint = { path = $(toml_string "$release_fips_path/crates/fips-endpoint") }
nvpn-fips-identity = { path = $(toml_string "$release_fips_path/crates/fips-identity") }
EOF
}

prepare_release_cargo_config() {
  if [[ -z "${NVPN_FIPS_REPO_PATH:-}" ]]; then
    return
  fi

  local fips_path="$NVPN_FIPS_REPO_PATH"
  local fips_head fips_tree
  if [[ ! -d "$fips_path" ]]; then
    echo "NVPN_FIPS_REPO_PATH does not exist: $fips_path" >&2
    exit 2
  fi
  fips_path="$(cd "$fips_path" && pwd -P)"
  release_fips_path="$fips_path"
  release_cargo_lock_original_sha256="$(release_file_sha256 "$ROOT_DIR/Cargo.lock")"
  release_cargo_manifest_original_sha256="$(release_file_sha256 "$ROOT_DIR/Cargo.toml")"
  for crate in fips-core fips-endpoint fips-identity; do
    if [[ ! -f "$fips_path/crates/$crate/Cargo.toml" ]]; then
      echo "NVPN_FIPS_REPO_PATH is missing crates/$crate/Cargo.toml: $fips_path" >&2
      exit 2
    fi
  done
  fips_head="$(git -C "$fips_path" rev-parse HEAD)" || {
    echo "NVPN_FIPS_REPO_PATH must be an exact Git checkout." >&2
    exit 2
  }
  require_exact_release_fips_revision "$fips_head" || exit 2
  fips_tree="$(git -C "$fips_path" rev-parse 'HEAD^{tree}')" || exit 2
  [[ -z "$(git -C "$fips_path" status --porcelain --untracked-files=all)" ]] || {
    echo "Release gate refuses a dirty local FIPS checkout." >&2
    exit 2
  }
  export NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD="$fips_head"
  export NVPN_LOCAL_FIPS_SESSION_FIPS_TREE="$fips_tree"
  export NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256="$(
    printf '%s' "$fips_path" | shasum -a 256 | awk '{print tolower($1)}'
  )"

  release_cargo_config_args+=(
    --config "patch.crates-io.nvpn-fips-core.path=\"$fips_path/crates/fips-core\""
    --config "patch.crates-io.nvpn-fips-endpoint.path=\"$fips_path/crates/fips-endpoint\""
    --config "patch.crates-io.nvpn-fips-identity.path=\"$fips_path/crates/fips-identity\""
  )
  echo "Using local FIPS crates from $fips_path"
  case "${NVPN_PATCH_LOCAL_FIPS:-1}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On)
      export NVPN_PATCH_LOCAL_FIPS=1
      echo "Using local FIPS crates in Docker e2e builds."
      ;;
    *)
      cat >&2 <<EOF
NVPN_FIPS_REPO_PATH requires NVPN_PATCH_LOCAL_FIPS=1 during the release gate so
Docker e2e builds test the same local FIPS crates as host Cargo.
EOF
      exit 2
      ;;
  esac
  install_release_cargo_config
  install_release_cargo_wrapper
  # Child mobile builders inherit the immutable Cargo patch above. Tell their
  # standalone local-FIPS helper not to append/restore the shared root manifest
  # while the Android and iOS physical lanes run concurrently.
  export NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED=1

  release_cargo_lock_backup="$(mktemp "${TMPDIR:-/tmp}/nvpn-release-gate-Cargo.lock.XXXXXX")"
  cp "$ROOT_DIR/Cargo.lock" "$release_cargo_lock_backup"
  if release_cargo metadata --locked --format-version=1 >/dev/null 2>/dev/null; then
    export NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256="$release_cargo_manifest_original_sha256"
    export NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256="$(
      release_file_sha256 "$ROOT_DIR/Cargo.lock"
    )"
    echo "Local FIPS crates satisfy existing Cargo.lock; skipping temporary lock refresh."
    return
  fi

  echo "Preparing temporary Cargo.lock for local FIPS path patches."
  release_cargo metadata --format-version=1 >/dev/null
  if ! release_cargo metadata --offline --format-version=1 >/dev/null; then
    cat >&2 <<EOF
Local FIPS crates do not satisfy Cargo.lock after a temporary metadata refresh.
Publish/update the FIPS crate versions and update nvpn's dependency/lock before
running the release gate with NVPN_FIPS_REPO_PATH.
EOF
    exit 2
  fi
  release_cargo_lock_args=(--offline)
  export NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256="$release_cargo_manifest_original_sha256"
  export NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256="$(
    release_file_sha256 "$ROOT_DIR/Cargo.lock"
  )"
  echo "Using offline Cargo resolution for local FIPS path patches."
}

run_local_fips_regression_tests() {
  if [[ -z "$release_fips_path" ]]; then
    return
  fi

  (
    cd "$release_fips_path"
    local_test() {
      local filter="$1"
      shift
      release_gate_cargo_test_filter nvpn-fips-core "$filter" cargo test -p nvpn-fips-core "$@"
    }
    local filter
    for filter in \
      overlay_adverts \
      update_peers \
      test_reply_learned_moves_configured_static_direct_peer_when_session_degraded \
      traversal_path_liveness_keeps_mobile_safe_floor \
      poll_nostr_discovery_configured_only_drops_nonconfigured_handoff \
      fresh_control_with_unreturned_endpoint_data_keeps_direct_without_fallback_peer \
      outbound_fmp_send_does_not_refresh_direct_path_liveness
    do
      local_test "$filter" "$filter" -- --nocapture
    done
    local_test initiate_reply_learned_keeps_configured_transit_inside_fanout_budget \
      proto::lookup::tests::initiate_reply_learned_keeps_configured_transit_inside_fanout_budget \
      -- --exact --nocapture
    local_test forward_reply_learned_keeps_configured_transit_inside_fanout_budget \
      proto::lookup::tests::forward_reply_learned_keeps_configured_transit_inside_fanout_budget \
      -- --exact --nocapture
    local_test persistent_two_seed_websocket_transit_survives_client_churn \
      --test public_websocket_transit \
      persistent_two_seed_websocket_transit_survives_client_churn \
      -- --exact --nocapture
  )
}

release_cargo() {
  if ((${#release_cargo_config_args[@]})); then
    cargo "${release_cargo_config_args[@]}" "$@"
  else
    cargo "$@"
  fi
}

release_gate_cargo_test_filter() (
  set -o pipefail
  local package="$1"
  local filter="$2"
  shift 2
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/nvpn-release-gate-test.XXXXXX")"
  if ! "$@" 2>&1 | tee "$output"; then
    rm -f "$output"
    return 1
  fi
  if ! awk -v filter="$filter" '
      $1 == "test" && index($0, filter) > 0 && $NF == "ok" { found = 1 }
      END { exit(found ? 0 : 1) }
    ' "$output"
  then
    printf 'Release gate test selector matched no passing test: %s (%s)\n' \
      "$filter" "$package" >&2
    rm -f "$output"
    return 1
  fi
  rm -f "$output"
)

release_cargo_test_filter() {
  local package="$1"
  local filter="$2"
  release_gate_cargo_test_filter "$package" "$filter" \
    release_cargo test "${release_cargo_lock_args[@]}" -p "$package" "$filter"
}

run_release_gate_candidate_preflight() {
  if ! command -v rg >/dev/null 2>&1; then
    echo "Release gate requires ripgrep (rg) for source contract harnesses." >&2
    return 1
  fi
  node scripts/sync-versions.mjs --check
  ./scripts/check-source-file-lines.sh
}

seal_release_gate_app_candidate() {
  local candidate_root app_sha app_tree configured_root
  candidate_root="$(cd "$ROOT_DIR" && pwd -P)" || return 1
  app_sha="$(git -C "$candidate_root" rev-parse HEAD)" || return 1
  app_tree="$(git -C "$candidate_root" rev-parse 'HEAD^{tree}')" || return 1

  if [[ -n "${NVPN_EXPECTED_APP_GIT_SHA:-}" \
    && "$NVPN_EXPECTED_APP_GIT_SHA" != "$app_sha" ]]
  then
    echo "Release gate app revision differs from NVPN_EXPECTED_APP_GIT_SHA." >&2
    return 1
  fi
  if [[ -n "${NVPN_EXPECTED_APP_GIT_TREE:-}" \
    && "$NVPN_EXPECTED_APP_GIT_TREE" != "$app_tree" ]]
  then
    echo "Release gate app tree differs from NVPN_EXPECTED_APP_GIT_TREE." >&2
    return 1
  fi
  if [[ -n "${NVPN_RELEASE_APP_REPO_PATH:-}" ]]; then
    configured_root="$(cd "$NVPN_RELEASE_APP_REPO_PATH" && pwd -P)" || {
      echo "Release gate could not resolve NVPN_RELEASE_APP_REPO_PATH." >&2
      return 1
    }
    [[ "$configured_root" == "$candidate_root" ]] || {
      echo "Release gate app path differs from its exact candidate checkout." >&2
      return 1
    }
  fi

  assert_release_checkout_state \
    "$candidate_root" "$app_sha" "$app_tree" "Release gate app candidate" \
    || return 1
  export NVPN_EXPECTED_APP_GIT_SHA="$app_sha"
  export NVPN_EXPECTED_APP_GIT_TREE="$app_tree"
  export NVPN_RELEASE_APP_REPO_PATH="$candidate_root"
}

run_release_gate_static_preflight() {
  npm ci
  npm run check
  npm run build
  if [[ "$(uname -s)" == "Darwin" ]]; then
    ./scripts/test-ios-generated-project.sh
    ./scripts/test-ios-qr-image-import-launch-environment.sh
    NVPN_IOS_RUST_PROFILE=release ./tools/run-ios xcframework
    ./scripts/test-ios-appstore-policy.sh
  else
    echo "Skipping iOS App Store binary-policy gate on this non-Apple host."
  fi
  cargo fmt --check
}

run_rust_validation_lane() {
  ./scripts/security-audit-rust.sh
  run_local_fips_regression_tests
  release_cargo clippy "${release_cargo_lock_args[@]}" --workspace --all-targets -- -D warnings
  export RUST_MIN_STACK="${RUST_MIN_STACK:-8388608}"
  # This fixture contains a strict end-to-end latency assertion. Keep it out of
  # the workspace suite while the cold Docker image may be compiling, then run
  # and measure it once after joining that build below.
  release_cargo test "${release_cargo_lock_args[@]}" --workspace -- \
    --test-threads=1 \
    --skip websocket_seed_router_routes_new_recipient_without_preconverged_roster_peer \
    --skip websocket_seed_router_retries_durable_join_receipt_after_first_route_failure \
    --skip websocket_seed_router_delivers_durable_join_receipt_after_tunnel_restart \
    --skip desktop_mobile_manual_join_desktop_admin_to_mobile_joiner \
    --skip desktop_mobile_manual_join_mobile_admin_to_desktop_joiner
  # Cross the desktop-daemon/mobile-tunnel boundary with each side acting as
  # admin once. These two were excluded from the workspace invocation above;
  # every other untimed Rust regression has already run there exactly once.
  release_cargo_test_filter nostr-vpn-app-core desktop_mobile_manual_join_desktop_admin_to_mobile_joiner
  release_cargo_test_filter nostr-vpn-app-core desktop_mobile_manual_join_mobile_admin_to_desktop_joiner
  ./scripts/e2e-manual-join-cli.sh
  ./scripts/e2e-update-cli.sh
}

run_host_validation_lane() {
  run_release_gate_static_preflight
  run_rust_validation_lane
}

run_android_static_validation_lane() {
  command -v gradle >/dev/null 2>&1 || {
    echo "Android static validation requires Gradle on PATH." >&2
    return 1
  }
  # Kotlin compilation, unit tests, and Android lint do not need to rebuild the
  # Rust shared library. Keep this lane independent from Cargo so it can overlap
  # the longer Rust validation lane without sharing build outputs.
  gradle -p android \
    "-Pkotlin.project.persistent.dir=$RELEASE_GATE_PARALLEL_LOG_DIR/android-kotlin-project" \
    :app:lintDebug \
    :app:testDebugUnitTest \
    -x buildRustArm64
}

windows_ssh_command() {
  local host="$1"
  WINDOWS_SSH_CMD=(ssh -o BatchMode=yes -o ConnectTimeout=5)
  if [[ -n "${NVPN_WINDOWS_SSH_PROXY_COMMAND:-}" ]]; then
    WINDOWS_SSH_CMD+=(-o "ProxyCommand=${NVPN_WINDOWS_SSH_PROXY_COMMAND}")
  elif [[ -n "${NVPN_WINDOWS_SSH_JUMP:-}" ]]; then
    WINDOWS_SSH_CMD+=(-J "$NVPN_WINDOWS_SSH_JUMP")
  fi
  WINDOWS_SSH_CMD+=("$host")
}

windows_vm_reachable() {
  local host="$1"
  [[ -n "$host" ]] || return 1
  windows_ssh_command "$host"
  "${WINDOWS_SSH_CMD[@]}" hostname >/dev/null 2>&1
}

windows_host_installer_receipt() {
  printf '%s\n' "${NVPN_WINDOWS_HOST_INSTALLER_RECEIPT_PATH:-$RELEASE_GATE_PARALLEL_LOG_DIR/windows-installer/installer-receipt.json}"
}

windows_host_source_fips_receipt() {
  printf '%s\n' "${NVPN_WINDOWS_HOST_SOURCE_FIPS_RECEIPT_PATH:-$RELEASE_GATE_PARALLEL_LOG_DIR/windows-installer/cratesio-source-receipt.json}"
}

windows_presealed_source_fips_receipt() {
  printf '%s\n' "$RELEASE_GATE_PARALLEL_LOG_DIR/windows-source/cratesio-source-receipt.json"
}

prepare_windows_source_fips_receipt() {
  local receipt temporary_receipt
  receipt="$(windows_presealed_source_fips_receipt)"
  temporary_receipt="$receipt.tmp.$$"
  mkdir -p "$(dirname "$receipt")"
  rm -f "$receipt" "$temporary_receipt"
  if ! node "$ROOT_DIR/scripts/release-source-verification.mjs" \
    windows-cratesio-source-receipt \
    "$(git -C "$ROOT_DIR" rev-parse HEAD)" \
    "$(git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}')" \
    "${NVPN_FIPS_REPO_PATH:?Windows source receipt requires NVPN_FIPS_REPO_PATH}" \
    "${NVPN_EXPECTED_FIPS_GIT_SHA:?Windows source receipt requires NVPN_EXPECTED_FIPS_GIT_SHA}" \
    "${NVPN_EXPECTED_FIPS_GIT_TREE:?Windows source receipt requires NVPN_EXPECTED_FIPS_GIT_TREE}" \
    "${NVPN_EXPECTED_FIPS_VERSION:?Windows source receipt requires NVPN_EXPECTED_FIPS_VERSION}" \
    >"$temporary_receipt"
  then
    rm -f "$temporary_receipt"
    return 1
  fi
  mv "$temporary_receipt" "$receipt"
  export NVPN_WINDOWS_PRESEALED_SOURCE_FIPS_RECEIPT_PATH="$receipt"
}

run_auto_windows_vm_app_smoke() {
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  if windows_vm_reachable "$host"; then
    release_gate_run_with_timeout "Windows VM app launch smoke" "$WINDOWS_GUI_SMOKE_TIMEOUT_SECS" \
      env NVPN_WINDOWS_INSTALLER_GATE_ARTIFACT_DIR="$RELEASE_GATE_PARALLEL_LOG_DIR/windows-installer" \
      NVPN_WINDOWS_PRESEALED_SOURCE_FIPS_RECEIPT_PATH="${NVPN_WINDOWS_PRESEALED_SOURCE_FIPS_RECEIPT_PATH:-}" \
      ./scripts/windows-vm-app-launch-smoke.sh "$host"
  else
    echo "Skipping Windows VM app launch smoke because ssh $host is unreachable."
  fi
}

run_auto_windows_vm_wireguard_exit_e2e() {
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  local installer_receipt source_fips_receipt
  installer_receipt="$(windows_host_installer_receipt)"
  source_fips_receipt="$(windows_host_source_fips_receipt)"
  if windows_vm_reachable "$host"; then
    release_gate_run_with_timeout "Windows WG exit e2e" "$WINDOWS_WG_EXIT_TIMEOUT_SECS" \
      env NVPN_WINDOWS_REQUIRE_WG_DIRECT_E2E=1 \
      NVPN_WINDOWS_HOST_INSTALLER_RECEIPT_PATH="$installer_receipt" \
      NVPN_WINDOWS_HOST_SOURCE_FIPS_RECEIPT_PATH="$source_fips_receipt" \
      ./scripts/windows-vm-wireguard-exit-e2e.sh "$host"
  else
    echo "Skipping Windows WG exit e2e because ssh $host is unreachable."
  fi
}

run_auto_windows_vm_manual_join_ui_e2e() {
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  if windows_vm_reachable "$host"; then
    release_gate_run_with_timeout "Windows manual-join UI e2e" \
      "$DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS" \
      ./scripts/windows-vm-manual-join-e2e.sh "$host"
  else
    echo "Skipping Windows manual-join UI e2e because ssh $host is unreachable."
  fi
}

run_auto_windows_vm_service_toggle_e2e() {
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  if windows_vm_reachable "$host"; then
    release_gate_run_with_timeout "Windows service-toggle UAC e2e" \
      "$DESKTOP_SERVICE_TOGGLE_TIMEOUT_SECS" \
      ./scripts/windows-vm-service-toggle-e2e.sh "$host"
  else
    echo "Skipping Windows service-toggle UAC e2e because ssh $host is unreachable."
  fi
}

release_gate_mode_disabled() {
  case "${1:-}" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off) return 0 ;;
    *) return 1 ;;
  esac
}

windows_platform_lane_requested() {
  ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E:-auto}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_WINDOWS_GUI_SMOKE:-auto}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_WINDOWS_MANUAL_JOIN_UI_E2E:-required}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_WINDOWS_DNS_UI_E2E:-required}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_WINDOWS_SERVICE_TOGGLE_E2E:-required}"
}

prepare_windows_platform_lane_sync() {
  WINDOWS_LANE_PRE_SYNCED=0
  windows_platform_lane_requested || return 0

  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  if windows_vm_reachable "$host"; then
    NVPN_WINDOWS_FIPS_REPO_PATH="$release_fips_path" \
      ./scripts/windows-vm-git-sync.sh "$host"
    write_platform_preparation_receipt \
      "$WINDOWS_PLATFORM_PREPARATION_RECEIPT" windows
    WINDOWS_LANE_PRE_SYNCED=1
  fi
}

run_windows_wireguard_exit_gate() {
  local installer_receipt source_fips_receipt
  installer_receipt="$(windows_host_installer_receipt)"
  source_fips_receipt="$(windows_host_source_fips_receipt)"
  case "${NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E:-auto}" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Windows WG exit e2e because NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E=${NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E}"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|windows-vm|required)
      release_gate_run_with_timeout "Windows WG exit e2e" "$WINDOWS_WG_EXIT_TIMEOUT_SECS" \
        env NVPN_WINDOWS_REQUIRE_WG_DIRECT_E2E=1 \
        NVPN_WINDOWS_HOST_INSTALLER_RECEIPT_PATH="$installer_receipt" \
        NVPN_WINDOWS_HOST_SOURCE_FIPS_RECEIPT_PATH="$source_fips_receipt" \
        ./scripts/windows-vm-wireguard-exit-e2e.sh "${NVPN_WINDOWS_SSH_HOST:-}"
      ;;
    auto|AUTO|Auto|"")
      run_auto_windows_vm_wireguard_exit_e2e
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E=${NVPN_RELEASE_GATE_WINDOWS_WG_EXIT_E2E}" >&2
      return 2
      ;;
  esac
}

run_windows_app_launch_gate() {
  local mode="${NVPN_RELEASE_GATE_WINDOWS_GUI_SMOKE:-auto}"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Windows app launch smoke because NVPN_RELEASE_GATE_WINDOWS_GUI_SMOKE=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|windows-vm)
      release_gate_run_with_timeout "Windows VM app launch smoke" "$WINDOWS_GUI_SMOKE_TIMEOUT_SECS" \
        env NVPN_WINDOWS_INSTALLER_GATE_ARTIFACT_DIR="$RELEASE_GATE_PARALLEL_LOG_DIR/windows-installer" \
        NVPN_WINDOWS_PRESEALED_SOURCE_FIPS_RECEIPT_PATH="${NVPN_WINDOWS_PRESEALED_SOURCE_FIPS_RECEIPT_PATH:-}" \
        ./scripts/windows-vm-app-launch-smoke.sh "${NVPN_WINDOWS_SSH_HOST:-}"
      ;;
    auto|AUTO|Auto|"")
      run_auto_windows_vm_app_smoke
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_WINDOWS_GUI_SMOKE=$mode" >&2
      return 2
      ;;
  esac
}

run_windows_manual_join_ui_gate() {
  local mode="${NVPN_RELEASE_GATE_WINDOWS_MANUAL_JOIN_UI_E2E:-required}"
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Windows manual-join UI e2e because NVPN_RELEASE_GATE_WINDOWS_MANUAL_JOIN_UI_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|windows-vm|required)
      windows_vm_reachable "$host" \
        || { echo "Required Windows manual-join UI VM is unreachable: $host" >&2; return 1; }
      release_gate_run_with_timeout "Windows manual-join UI e2e" \
        "$DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS" \
        ./scripts/windows-vm-manual-join-e2e.sh "$host"
      ;;
    auto|AUTO|Auto|"")
      run_auto_windows_vm_manual_join_ui_e2e
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_WINDOWS_MANUAL_JOIN_UI_E2E=$mode" >&2
      return 2
      ;;
  esac
}

run_windows_service_toggle_gate() {
  local mode="${NVPN_RELEASE_GATE_WINDOWS_SERVICE_TOGGLE_E2E:-required}"
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Windows service-toggle UAC e2e because NVPN_RELEASE_GATE_WINDOWS_SERVICE_TOGGLE_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|windows-vm|required)
      windows_vm_reachable "$host" \
        || { echo "Required Windows service-toggle VM is unreachable: $host" >&2; return 1; }
      release_gate_run_with_timeout "Windows service-toggle UAC e2e" \
        "$DESKTOP_SERVICE_TOGGLE_TIMEOUT_SECS" \
        ./scripts/windows-vm-service-toggle-e2e.sh "$host"
      ;;
    auto|AUTO|Auto|"")
      run_auto_windows_vm_service_toggle_e2e
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_WINDOWS_SERVICE_TOGGLE_E2E=$mode" >&2
      return 2
      ;;
  esac
}

run_windows_exit_dns_ui_gate() {
  local mode="${NVPN_RELEASE_GATE_WINDOWS_DNS_UI_E2E:-required}"
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  local artifact_dir="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-dns-ui/windows"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Windows Exit DNS UI e2e because NVPN_RELEASE_GATE_WINDOWS_DNS_UI_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|windows-vm|required)
      windows_vm_reachable "$host" \
        || { echo "Required Windows Exit DNS UI VM is unreachable: $host" >&2; return 1; }
      release_gate_run_with_timeout "Windows Exit DNS UI save/relaunch/readback" \
        "$DESKTOP_DNS_UI_TIMEOUT_SECS" \
        env \
          NVPN_DESKTOP_DNS_UI_ARTIFACT_DIR="$artifact_dir" \
          ./scripts/windows-vm-exit-dns-ui-e2e.sh "$host"
      ;;
    auto|AUTO|Auto|"")
      if windows_vm_reachable "$host"; then
        release_gate_run_with_timeout "Windows Exit DNS UI save/relaunch/readback" \
          "$DESKTOP_DNS_UI_TIMEOUT_SECS" \
          env \
            NVPN_DESKTOP_DNS_UI_ARTIFACT_DIR="$artifact_dir" \
            ./scripts/windows-vm-exit-dns-ui-e2e.sh "$host"
      else
        echo "Skipping Windows Exit DNS UI e2e because its isolated VM is unreachable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_WINDOWS_DNS_UI_E2E=$mode" >&2
      return 2
      ;;
  esac
}

windows_underlay_gate_reachable() {
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  local hypervisor="${NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH:-}"
  local vm="${NVPN_WINDOWS_UNDERLAY_VM_NAME:-${NVPN_WINDOWS_VM_NAME:-}}"
  [[ -n "$host" && -n "$hypervisor" && -n "$vm" ]] || return 1
  windows_vm_reachable "$host" || return 1
  ssh -o BatchMode=yes -o ConnectTimeout=5 "$hypervisor" \
    "virsh dominfo '$vm'" >/dev/null 2>&1
}

require_windows_underlay_gate() {
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  local hypervisor="${NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH:-}"
  local vm="${NVPN_WINDOWS_UNDERLAY_VM_NAME:-${NVPN_WINDOWS_VM_NAME:-}}"
  [[ -n "$host" ]] || {
    echo "Required Windows underlay gate needs NVPN_WINDOWS_SSH_HOST." >&2
    return 1
  }
  [[ -n "$hypervisor" ]] || {
    echo "Required Windows underlay gate needs NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH." >&2
    return 1
  }
  [[ -n "$vm" ]] || {
    echo "Required Windows underlay gate needs NVPN_WINDOWS_UNDERLAY_VM_NAME." >&2
    return 1
  }
  windows_underlay_gate_reachable || {
    echo "Required Windows underlay VM/hypervisor is unreachable." >&2
    return 1
  }
}

run_windows_underlay_network_change_gate() {
  local mode="${NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E:-auto}"
  local artifact_dir="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-network/windows-artifacts"
  local receipt="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-network/windows.json"
  local installer_receipt source_fips_receipt installer_guest_repo
  local installer_guest_artifact_root exact_cli_path guest_installer_receipt
  installer_receipt="$(windows_host_installer_receipt)"
  source_fips_receipt="$(windows_host_source_fips_receipt)"
  installer_guest_repo="${NVPN_WINDOWS_GUEST_REPO_PATH:-C:\\src\\nostr-vpn}"
  installer_guest_artifact_root="${GUEST_ARTIFACT_ROOT:-C:\\src\\nostr-vpn\\artifacts}"
  exact_cli_path="${NVPN_WINDOWS_EXACT_CLI_PATH:-$installer_guest_repo\\windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish\\nvpn.exe}"
  guest_installer_receipt="${NVPN_WINDOWS_INSTALLER_RECEIPT_PATH:-$installer_guest_artifact_root\\windows-installer-gate\\installer-receipt.json}"
  local ran=0
  rm -rf "$artifact_dir"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Windows real underlay network-change e2e because NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|required)
      require_windows_underlay_gate
      release_gate_run_with_timeout "Windows real underlay network-change and DNS e2e" \
        "$DESKTOP_UNDERLAY_NETWORK_CHANGE_TIMEOUT_SECS" \
        env NVPN_DESKTOP_UNDERLAY_ARTIFACT_DIR="$artifact_dir" \
        NVPN_WINDOWS_EXACT_CLI_PATH="$exact_cli_path" \
        NVPN_WINDOWS_INSTALLER_RECEIPT_PATH="$guest_installer_receipt" \
        NVPN_WINDOWS_HOST_INSTALLER_RECEIPT_PATH="$installer_receipt" \
        NVPN_WINDOWS_HOST_SOURCE_FIPS_RECEIPT_PATH="$source_fips_receipt" \
        ./scripts/windows-vm-desktop-underlay-change-e2e.sh
      ran=1
      ;;
    auto|AUTO|Auto|"")
      if windows_underlay_gate_reachable; then
        release_gate_run_with_timeout "Windows real underlay network-change and DNS e2e" \
          "$DESKTOP_UNDERLAY_NETWORK_CHANGE_TIMEOUT_SECS" \
          env NVPN_DESKTOP_UNDERLAY_ARTIFACT_DIR="$artifact_dir" \
          NVPN_WINDOWS_EXACT_CLI_PATH="$exact_cli_path" \
          NVPN_WINDOWS_INSTALLER_RECEIPT_PATH="$guest_installer_receipt" \
          NVPN_WINDOWS_HOST_INSTALLER_RECEIPT_PATH="$installer_receipt" \
          NVPN_WINDOWS_HOST_SOURCE_FIPS_RECEIPT_PATH="$source_fips_receipt" \
          ./scripts/windows-vm-desktop-underlay-change-e2e.sh
        ran=1
      else
        echo "Skipping Windows real underlay network-change e2e because its isolated VM/hypervisor is unavailable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_WINDOWS_UNDERLAY_NETWORK_CHANGE_E2E=$mode" >&2
      return 2
      ;;
  esac
  if [[ "$ran" -eq 1 ]]; then
    python3 "$ROOT_DIR/scripts/release-network-evidence.py" desktop \
      --platform windows \
      --artifact-dir "$artifact_dir" \
      --dns-ui-dir "$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-dns-ui/windows" \
      --app-git-sha "$(git -C "$ROOT_DIR" rev-parse HEAD)" \
      --app-git-tree "$(git -C "$ROOT_DIR" rev-parse HEAD^{tree})" \
      --output "$receipt"
  fi
}

run_windows_platform_lane() {
  if [[ "${WINDOWS_LANE_PRE_SYNCED:-0}" != "1" ]]; then
    prepare_windows_platform_lane_sync
  fi
  if [[ "${WINDOWS_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_WINDOWS_SKIP_GIT_SYNC=1
  fi
  run_windows_app_launch_gate
  run_windows_manual_join_ui_gate
  run_windows_exit_dns_ui_gate
  run_windows_service_toggle_gate
}

macos_vm_reachable() {
  [[ -n "${NVPN_MACOS_SSH_HOST:-}" ]] || return 1
  macos_vm_require_isolated_target "$NVPN_MACOS_SSH_HOST"
}

macos_platform_lane_requested() {
  ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_MACOS_MANUAL_JOIN_UI_E2E:-required}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_MACOS_DNS_UI_E2E:-required}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_MACOS_SERVICE_TOGGLE_E2E:-required}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E:-auto}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_MACOS_GUI_SMOKE:-auto}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU:-auto}"
}

prepare_macos_platform_lane_sync() {
  MACOS_PLATFORM_LANE_PRE_SYNCED=0
  macos_platform_lane_requested || return 0
  if macos_vm_reachable; then
    local artifact_status=0
    env NVPN_MACOS_RUST_PROFILE=release NVPN_MACOS_XCODE_CONFIGURATION=Release \
      NVPN_MACOS_RELEASE_ARTIFACT_ACTION=prepare-only \
      ./scripts/macos-vm-release-mobile-join-e2e.sh \
        "${NVPN_MACOS_SSH_HOST:-}" \
      || artifact_status="$?"
    if [[ "$artifact_status" -ne 0 ]]; then
      return 1
    fi
    write_platform_preparation_receipt \
      "$MACOS_PLATFORM_PREPARATION_RECEIPT" macos
    MACOS_PLATFORM_LANE_PRE_SYNCED=1
    export NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY=1
  fi
}

run_macos_manual_join_ui_gate() {
  local mode="${NVPN_RELEASE_GATE_MACOS_MANUAL_JOIN_UI_E2E:-required}"
  if [[ "${MACOS_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_MACOS_SKIP_GIT_SYNC=1
  fi
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping macOS manual-join UI e2e because NVPN_RELEASE_GATE_MACOS_MANUAL_JOIN_UI_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|macos-vm|required)
      macos_vm_reachable \
        || { echo "Required macOS manual-join UI VM is unreachable." >&2; return 1; }
      release_gate_run_with_timeout "macOS manual-join UI e2e" \
        "$DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS" \
        ./scripts/macos-vm-manual-join-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      ;;
    local)
      release_gate_run_with_timeout "macOS manual-join UI e2e" \
        "$DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS" \
        ./scripts/e2e-macos-manual-join-ui.sh
      ;;
    auto|AUTO|Auto|"")
      if macos_vm_reachable; then
        release_gate_run_with_timeout "macOS manual-join UI e2e" \
          "$DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS" \
          ./scripts/macos-vm-manual-join-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      else
        echo "Skipping macOS manual-join UI e2e because its isolated VM is unreachable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MACOS_MANUAL_JOIN_UI_E2E=$mode" >&2
      return 2
      ;;
  esac
}

run_macos_service_toggle_gate() {
  local mode="${NVPN_RELEASE_GATE_MACOS_SERVICE_TOGGLE_E2E:-required}"
  if [[ "${MACOS_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_MACOS_SKIP_GIT_SYNC=1
  fi
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping macOS service-toggle Authorization e2e because NVPN_RELEASE_GATE_MACOS_SERVICE_TOGGLE_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|macos-vm|required)
      macos_vm_reachable \
        || { echo "Required macOS service-toggle VM is unreachable." >&2; return 1; }
      release_gate_run_with_timeout "macOS service-toggle Authorization e2e" \
        "$DESKTOP_SERVICE_TOGGLE_TIMEOUT_SECS" \
        ./scripts/macos-vm-service-toggle-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      ;;
    auto|AUTO|Auto|"")
      if macos_vm_reachable; then
        release_gate_run_with_timeout "macOS service-toggle Authorization e2e" \
          "$DESKTOP_SERVICE_TOGGLE_TIMEOUT_SECS" \
          ./scripts/macos-vm-service-toggle-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      else
        echo "Skipping macOS service-toggle Authorization e2e because its isolated VM is unreachable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MACOS_SERVICE_TOGGLE_E2E=$mode" >&2
      return 2
      ;;
  esac
}

run_macos_exit_dns_ui_gate() {
  local mode="${NVPN_RELEASE_GATE_MACOS_DNS_UI_E2E:-required}"
  local artifact_dir="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-dns-ui/macos"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping macOS Exit DNS UI e2e because NVPN_RELEASE_GATE_MACOS_DNS_UI_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|macos-vm|required)
      macos_vm_reachable \
        || { echo "Required macOS Exit DNS UI VM is unreachable." >&2; return 1; }
      release_gate_run_with_timeout "macOS Exit DNS UI save/relaunch/readback" \
        "$DESKTOP_DNS_UI_TIMEOUT_SECS" \
        env NVPN_DESKTOP_DNS_UI_ARTIFACT_DIR="$artifact_dir" \
        ./scripts/macos-vm-release-exit-dns-ui-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      ;;
    auto|AUTO|Auto|"")
      if macos_vm_reachable; then
        release_gate_run_with_timeout "macOS Exit DNS UI save/relaunch/readback" \
          "$DESKTOP_DNS_UI_TIMEOUT_SECS" \
          env NVPN_DESKTOP_DNS_UI_ARTIFACT_DIR="$artifact_dir" \
          ./scripts/macos-vm-release-exit-dns-ui-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      else
        echo "Skipping macOS Exit DNS UI e2e because its isolated VM is unreachable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MACOS_DNS_UI_E2E=$mode" >&2
      return 2
      ;;
  esac
}

run_macos_platform_lane() {
  if [[ "${MACOS_PLATFORM_LANE_PRE_SYNCED:-0}" != "1" ]]; then
    prepare_macos_platform_lane_sync
  fi
  run_macos_manual_join_ui_gate
  run_macos_exit_dns_ui_gate
  run_macos_service_toggle_gate
}

ubuntu_ssh_command() {
  local host="$1"
  UBUNTU_SSH_CMD=(ssh -o BatchMode=yes -o ConnectTimeout=5)
  if [[ -n "${NVPN_UBUNTU_SSH_PROXY_COMMAND:-}" ]]; then
    UBUNTU_SSH_CMD+=(
      -o "ProxyCommand=${NVPN_UBUNTU_SSH_PROXY_COMMAND}"
    )
  elif [[ -n "${NVPN_UBUNTU_SSH_JUMP:-}" ]]; then
    UBUNTU_SSH_CMD+=(-J "$NVPN_UBUNTU_SSH_JUMP")
  fi
  UBUNTU_SSH_CMD+=("$host")
}

ubuntu_vm_reachable() {
  local host="${NVPN_UBUNTU_SSH_HOST:-}"
  [[ -n "$host" ]] || return 1
  ubuntu_ssh_command "$host"
  "${UBUNTU_SSH_CMD[@]}" hostname >/dev/null 2>&1
}

linux_platform_lane_requested() {
  ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_LINUX_MANUAL_JOIN_UI_E2E:-required}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_LINUX_DNS_UI_E2E:-required}" \
    || ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_LINUX_SERVICE_TOGGLE_E2E:-required}"
}

prepare_host_linux_vm_bundle_and_record() {
  local bundle receipt temporary
  if [[ -z "${NVPN_HOST_LINUX_VM_BUILDER_MODE:-}" \
    && -n "${NVPN_UBUNTU_SSH_HOST:-}" ]]
  then
    export NVPN_HOST_LINUX_VM_BUILDER_MODE=remote-native
    export NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST="${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST:-$NVPN_UBUNTU_SSH_HOST}"
    if [[ "$NVPN_HOST_LINUX_VM_NATIVE_BUILDER_HOST" == "$NVPN_UBUNTU_SSH_HOST" \
      && -z "${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND:-}" \
      && -z "${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_JUMP:-}" ]]
    then
      export NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND="${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_PROXY_COMMAND:-${NVPN_UBUNTU_SSH_PROXY_COMMAND:-}}"
      export NVPN_HOST_LINUX_VM_NATIVE_BUILDER_JUMP="${NVPN_HOST_LINUX_VM_NATIVE_BUILDER_JUMP:-${NVPN_UBUNTU_SSH_JUMP:-}}"
    fi
  fi
  bundle="$(./scripts/prepare-host-linux-vm-bundle.sh)"
  [[ "$bundle" == /* && -d "$bundle" && ! -L "$bundle" ]] \
    || { echo "Host Linux VM bundle builder returned an invalid path." >&2; return 1; }
  NVPN_HOST_LINUX_VM_BUNDLE_DIR="$bundle"
  export NVPN_HOST_LINUX_VM_BUNDLE_DIR

  receipt="${HOST_LINUX_VM_BUNDLE_PATH_RECEIPT:-}"
  [[ -n "$receipt" ]] || return 0
  temporary="${receipt}.tmp.$$"
  (
    umask 077
    printf '%s\n' "$bundle" >"$temporary"
  )
  mv -f "$temporary" "$receipt"
}

load_host_linux_vm_bundle_path_receipt() {
  local receipt="${HOST_LINUX_VM_BUNDLE_PATH_RECEIPT:-}"
  local bundle line_count
  [[ -n "$receipt" && -f "$receipt" && ! -L "$receipt" ]] \
    || { echo "Host Linux VM bundle path receipt is missing." >&2; return 1; }
  line_count="$(wc -l <"$receipt" | tr -d '[:space:]')"
  [[ "$line_count" == "1" ]] \
    || { echo "Host Linux VM bundle path receipt is invalid." >&2; return 1; }
  IFS= read -r bundle <"$receipt"
  [[ "$bundle" == /* && -d "$bundle" && ! -L "$bundle" ]] \
    || { echo "Host Linux VM bundle path receipt is invalid." >&2; return 1; }
  NVPN_HOST_LINUX_VM_BUNDLE_DIR="$bundle"
  export NVPN_HOST_LINUX_VM_BUNDLE_DIR
}

prepare_linux_platform_lane_sync() {
  LINUX_PLATFORM_LANE_PRE_SYNCED=0
  linux_platform_lane_requested || return 0
  if ubuntu_vm_reachable; then
    ./scripts/ubuntu-vm-git-sync.sh \
      "${NVPN_UBUNTU_SSH_HOST:-}"
    local ROOT="$ROOT_DIR"
    local SSH_HOST="${NVPN_UBUNTU_SSH_HOST:-}"
    local GUEST_SRC_ROOT="${NVPN_UBUNTU_GUEST_SRC_ROOT:-src}"
    local GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn-release-gate"
    ubuntu_vm_recover_stale_imported_release_bundle
    prepare_host_linux_vm_bundle_and_record
    write_platform_preparation_receipt \
      "$LINUX_PLATFORM_PREPARATION_RECEIPT" linux
    LINUX_PLATFORM_LANE_PRE_SYNCED=1
  fi
}

run_linux_manual_join_ui_gate() {
  local mode="${NVPN_RELEASE_GATE_LINUX_MANUAL_JOIN_UI_E2E:-required}"
  local host="${NVPN_UBUNTU_SSH_HOST:-}"
  if [[ "${LINUX_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_UBUNTU_SKIP_GIT_SYNC=1
  fi
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Linux manual-join UI e2e because NVPN_RELEASE_GATE_LINUX_MANUAL_JOIN_UI_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|ubuntu-vm|required)
      ubuntu_vm_reachable \
        || { echo "Required Linux manual-join UI VM is unreachable: $host" >&2; return 1; }
      release_gate_run_with_timeout "Linux manual-join UI e2e" \
        "$DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS" \
        ./scripts/ubuntu-vm-manual-join-e2e.sh "$host"
      ;;
    auto|AUTO|Auto|"")
      if ubuntu_vm_reachable; then
        release_gate_run_with_timeout "Linux manual-join UI e2e" \
          "$DESKTOP_MANUAL_JOIN_UI_TIMEOUT_SECS" \
          ./scripts/ubuntu-vm-manual-join-e2e.sh "$host"
      else
        echo "Skipping Linux manual-join UI e2e because its isolated VM is unreachable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_LINUX_MANUAL_JOIN_UI_E2E=$mode" >&2
      return 2
      ;;
  esac
}

run_linux_exit_dns_ui_gate() {
  local mode="${NVPN_RELEASE_GATE_LINUX_DNS_UI_E2E:-required}"
  local host="${NVPN_UBUNTU_SSH_HOST:-}"
  local artifact_dir="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-dns-ui/linux"
  if [[ "${LINUX_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_UBUNTU_SKIP_GIT_SYNC=1
  fi
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Linux Exit DNS UI e2e because NVPN_RELEASE_GATE_LINUX_DNS_UI_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|ubuntu-vm|required)
      ubuntu_vm_reachable \
        || { echo "Required Linux Exit DNS UI VM is unreachable: $host" >&2; return 1; }
      release_gate_run_with_timeout "Linux Exit DNS UI save/relaunch/readback" \
        "$DESKTOP_DNS_UI_TIMEOUT_SECS" \
        env NVPN_DESKTOP_DNS_UI_ARTIFACT_DIR="$artifact_dir" \
        ./scripts/ubuntu-vm-exit-dns-ui-e2e.sh "$host"
      ;;
    auto|AUTO|Auto|"")
      if ubuntu_vm_reachable; then
        release_gate_run_with_timeout "Linux Exit DNS UI save/relaunch/readback" \
          "$DESKTOP_DNS_UI_TIMEOUT_SECS" \
          env NVPN_DESKTOP_DNS_UI_ARTIFACT_DIR="$artifact_dir" \
          ./scripts/ubuntu-vm-exit-dns-ui-e2e.sh "$host"
      else
        echo "Skipping Linux Exit DNS UI e2e because its isolated VM is unreachable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_LINUX_DNS_UI_E2E=$mode" >&2
      return 2
      ;;
  esac
}

run_linux_service_toggle_gate() {
  local mode="${NVPN_RELEASE_GATE_LINUX_SERVICE_TOGGLE_E2E:-required}"
  local host="${NVPN_UBUNTU_SSH_HOST:-}"
  if [[ "${LINUX_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_UBUNTU_SKIP_GIT_SYNC=1
  fi
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Linux service-toggle PolicyKit e2e because NVPN_RELEASE_GATE_LINUX_SERVICE_TOGGLE_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|ubuntu-vm|required)
      ubuntu_vm_reachable \
        || { echo "Required Linux service-toggle VM is unreachable: $host" >&2; return 1; }
      release_gate_run_with_timeout "Linux service-toggle PolicyKit e2e" \
        "$DESKTOP_SERVICE_TOGGLE_TIMEOUT_SECS" \
        ./scripts/ubuntu-vm-service-toggle-e2e.sh "$host"
      ;;
    auto|AUTO|Auto|"")
      if ubuntu_vm_reachable; then
        release_gate_run_with_timeout "Linux service-toggle PolicyKit e2e" \
          "$DESKTOP_SERVICE_TOGGLE_TIMEOUT_SECS" \
          ./scripts/ubuntu-vm-service-toggle-e2e.sh "$host"
      else
        echo "Skipping Linux service-toggle PolicyKit e2e because its isolated VM is unreachable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_LINUX_SERVICE_TOGGLE_E2E=$mode" >&2
      return 2
      ;;
  esac
}

linux_underlay_gate_reachable() {
  local hypervisor="${NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH:-}"
  local vm="${NVPN_LINUX_UNDERLAY_VM_NAME:-${NVPN_UBUNTU_VM_NAME:-}}"
  [[ -n "${NVPN_UBUNTU_SSH_HOST:-}" && -n "$hypervisor" && -n "$vm" ]] \
    || return 1
  ubuntu_vm_reachable || return 1
  ssh -o BatchMode=yes -o ConnectTimeout=5 "$hypervisor" \
    "virsh dominfo '$vm'" >/dev/null 2>&1
}

require_linux_underlay_gate() {
  local hypervisor="${NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH:-}"
  local vm="${NVPN_LINUX_UNDERLAY_VM_NAME:-${NVPN_UBUNTU_VM_NAME:-}}"
  [[ -n "${NVPN_UBUNTU_SSH_HOST:-}" ]] || {
    echo "Required Linux underlay gate needs NVPN_UBUNTU_SSH_HOST." >&2
    return 1
  }
  [[ -n "$hypervisor" ]] || {
    echo "Required Linux underlay gate needs NVPN_DESKTOP_UNDERLAY_HYPERVISOR_SSH." >&2
    return 1
  }
  [[ -n "$vm" ]] || {
    echo "Required Linux underlay gate needs NVPN_LINUX_UNDERLAY_VM_NAME." >&2
    return 1
  }
  linux_underlay_gate_reachable || {
    echo "Required Linux underlay VM/hypervisor is unreachable." >&2
    return 1
  }
}

run_linux_underlay_network_change_gate() {
  local mode="${NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E:-auto}"
  local artifact_dir="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-network/linux-artifacts"
  local receipt="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-network/linux.json"
  local ran=0
  rm -rf "$artifact_dir"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Linux real underlay network-change e2e because NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E=$mode"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|required)
      require_linux_underlay_gate
      NVPN_RELEASE_GATE_TIMEOUT_KILL_AFTER_SECS=90 \
        release_gate_run_with_timeout "Linux real underlay network-change and DNS e2e" \
        "$DESKTOP_UNDERLAY_NETWORK_CHANGE_TIMEOUT_SECS" \
        env NVPN_LINUX_UNDERLAY_ARTIFACT_DIR="$artifact_dir" \
        ./scripts/linux-vm-desktop-underlay-change-e2e.sh
      ran=1
      ;;
    auto|AUTO|Auto|"")
      if linux_underlay_gate_reachable; then
        NVPN_RELEASE_GATE_TIMEOUT_KILL_AFTER_SECS=90 \
          release_gate_run_with_timeout "Linux real underlay network-change and DNS e2e" \
          "$DESKTOP_UNDERLAY_NETWORK_CHANGE_TIMEOUT_SECS" \
          env NVPN_LINUX_UNDERLAY_ARTIFACT_DIR="$artifact_dir" \
          ./scripts/linux-vm-desktop-underlay-change-e2e.sh
        ran=1
      else
        echo "Skipping Linux real underlay network-change e2e because its isolated VM/hypervisor is unavailable."
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_LINUX_UNDERLAY_NETWORK_CHANGE_E2E=$mode" >&2
      return 2
      ;;
  esac
  if [[ "$ran" -eq 1 ]]; then
    python3 "$ROOT_DIR/scripts/release-network-evidence.py" desktop \
      --platform linux \
      --artifact-dir "$artifact_dir" \
      --dns-ui-dir "$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-dns-ui/linux" \
      --app-git-sha "$(git -C "$ROOT_DIR" rev-parse HEAD)" \
      --app-git-tree "$(git -C "$ROOT_DIR" rev-parse HEAD^{tree})" \
      --output "$receipt"
  fi
}

run_linux_platform_lane() {
  if [[ "${LINUX_PLATFORM_LANE_PRE_SYNCED:-0}" != "1" ]]; then
    prepare_linux_platform_lane_sync
  fi
  run_linux_manual_join_ui_gate
  run_linux_exit_dns_ui_gate
  release_gate_run_with_timeout "Linux paid-exit seller UI save/relaunch/readback" \
    "$PAID_EXIT_SELLER_UI_TIMEOUT_SECS" \
    env NVPN_PAID_EXIT_SELLER_UI_ARTIFACT_DIR="$RELEASE_GATE_PARALLEL_LOG_DIR/paid-exit-seller-ui/linux" \
    ./scripts/ubuntu-vm-paid-exit-seller-ui-e2e.sh "${NVPN_UBUNTU_SSH_HOST:-}"
  run_linux_service_toggle_gate
}

run_linux_exclusive_desktop_gates() {
  run_linux_underlay_network_change_gate
}

run_windows_exclusive_desktop_gates() {
  run_windows_wireguard_exit_gate
  run_windows_underlay_network_change_gate
}

run_macos_exclusive_desktop_gates() {
  run_wireguard_exit_platform_gates
}

release_gate_perf_output_dir() {
  if [[ -n "${NVPN_RELEASE_GATE_PERF_OUTPUT_DIR:-}" ]]; then
    printf '%s\n' "$NVPN_RELEASE_GATE_PERF_OUTPUT_DIR"
  elif [[ -n "${NVPN_PERF_OUTPUT_DIR:-}" ]]; then
    printf '%s\n' "$NVPN_PERF_OUTPUT_DIR"
  else
    printf '%s/artifacts/release-gate-nvpn-fips-perf-%s\n' \
      "$ROOT_DIR" "$(date -u +%Y%m%dT%H%M%SZ)"
  fi
}

run_wireguard_exit_platform_gates() {
  local artifact_dir="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-network/macos-artifacts"
  local receipt="$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-network/macos.json"
  local ran=0
  rm -rf "$artifact_dir"
  if [[ "${MACOS_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_MACOS_SKIP_GIT_SYNC=1
  fi
  case "${NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E:-auto}" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping macOS WG exit e2e because NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E=${NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E}"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|macos-vm|required)
      macos_vm_reachable \
        || { echo "Required macOS WG exit VM is unreachable." >&2; return 1; }
      release_gate_run_with_timeout "macOS VM WG exit e2e" "$MACOS_WG_EXIT_TIMEOUT_SECS" \
        env NVPN_MACOS_NETWORK_ARTIFACT_DIR="$artifact_dir" \
        ./scripts/macos-vm-desktop-wireguard-exit-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      ran=1
      ;;
    auto|AUTO|Auto|"")
      if macos_vm_reachable; then
        release_gate_run_with_timeout "macOS VM WG exit e2e" "$MACOS_WG_EXIT_TIMEOUT_SECS" \
          env NVPN_MACOS_NETWORK_ARTIFACT_DIR="$artifact_dir" \
          ./scripts/macos-vm-desktop-wireguard-exit-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
        ran=1
      else
        echo "Skipping macOS WG exit e2e because its isolated VM is unreachable."
      fi
      ;;
    local)
      echo "NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E=local is forbidden: release verification never mutates host routes." >&2
      return 2
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E=${NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E}" >&2
      return 2
      ;;
  esac
  if [[ "$ran" -eq 1 ]]; then
    python3 "$ROOT_DIR/scripts/release-network-evidence.py" desktop \
      --platform macos \
      --artifact-dir "$artifact_dir" \
      --dns-ui-dir "$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-dns-ui/macos/cases" \
      --artifact-receipt "${NVPN_RELEASE_JOIN_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-release-join}/macos/artifact.json" \
      --app-git-sha "$(git -C "$ROOT_DIR" rev-parse HEAD)" \
      --app-git-tree "$(git -C "$ROOT_DIR" rev-parse HEAD^{tree})" \
      --output "$receipt"
  fi
}

run_desktop_app_launch_smokes() {
  local linux_gui_smoke_default=1
  case "${NVPN_RELEASE_GATE_DOCKER_E2E:-1}" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      linux_gui_smoke_default=0
      ;;
  esac

  local linux_gui_smoke="${NVPN_RELEASE_GATE_LINUX_GUI_SMOKE:-$linux_gui_smoke_default}"
  case "$linux_gui_smoke" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Linux GUI launch smoke because NVPN_RELEASE_GATE_LINUX_GUI_SMOKE=$linux_gui_smoke"
      ;;
    *)
      if [[ -n "$release_fips_path" ]]; then
        release_gate_run_with_timeout "Linux GUI launch smoke" "$LINUX_GUI_SMOKE_TIMEOUT_SECS" \
          env NVPN_LINUX_NONINTERACTIVE=1 NVPN_LINUX_ISOLATE_LOCKFILES=1 \
          NVPN_LINUX_FIPS_REPO_PATH="$release_fips_path" \
          ./tools/run-linux env NVPN_PATCH_LOCAL_FIPS=1 NVPN_FIPS_REPO_PATH=/workspace/fips ./scripts/e2e-smoke.sh
      else
        release_gate_run_with_timeout "Linux GUI launch smoke" "$LINUX_GUI_SMOKE_TIMEOUT_SECS" \
          env NVPN_LINUX_NONINTERACTIVE=1 NVPN_LINUX_ISOLATE_LOCKFILES=1 \
          ./tools/run-linux ./scripts/e2e-smoke.sh
      fi
      ;;
  esac

  local macos_gui_smoke="${NVPN_RELEASE_GATE_MACOS_GUI_SMOKE:-auto}"
  if [[ "${MACOS_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_MACOS_SKIP_GIT_SYNC=1
  fi
  case "$macos_gui_smoke" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping macOS app launch smoke because NVPN_RELEASE_GATE_MACOS_GUI_SMOKE=$macos_gui_smoke"
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|macos-vm|required)
      macos_vm_reachable \
        || { echo "Required macOS app launch VM is unreachable." >&2; return 1; }
      release_gate_run_with_timeout "macOS VM app launch smoke" "$MACOS_GUI_SMOKE_TIMEOUT_SECS" \
        ./scripts/macos-vm-desktop-app-launch-smoke.sh "${NVPN_MACOS_SSH_HOST:-}"
      ;;
    auto|AUTO|Auto|"")
      if macos_vm_reachable; then
        release_gate_run_with_timeout "macOS VM app launch smoke" "$MACOS_GUI_SMOKE_TIMEOUT_SECS" \
          ./scripts/macos-vm-desktop-app-launch-smoke.sh "${NVPN_MACOS_SSH_HOST:-}"
      else
        echo "Skipping macOS app launch smoke because its isolated VM is unreachable."
      fi
      ;;
    local)
      echo "NVPN_RELEASE_GATE_MACOS_GUI_SMOKE=local is forbidden: release verification never launches the app against host state." >&2
      return 2
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MACOS_GUI_SMOKE=$macos_gui_smoke" >&2
      return 2
      ;;
  esac

}

run_macos_daemon_idle_cpu_gate() {
  local mode="${NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU:-auto}"
  if [[ "${MACOS_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]]; then
    export NVPN_MACOS_SKIP_GIT_SYNC=1
  fi
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping macOS daemon idle CPU gate because NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU=$mode"
      return
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|macos-vm|required)
      macos_vm_reachable \
        || { echo "Required macOS daemon idle CPU VM is unreachable." >&2; return 1; }
      release_gate_run_with_timeout "macOS VM daemon idle CPU" \
        "$MACOS_DAEMON_IDLE_CPU_TIMEOUT_SECS" \
        ./scripts/macos-vm-desktop-daemon-idle-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      return
      ;;
    auto|AUTO|Auto|"")
      if macos_vm_reachable; then
        release_gate_run_with_timeout "macOS VM daemon idle CPU" \
          "$MACOS_DAEMON_IDLE_CPU_TIMEOUT_SECS" \
          ./scripts/macos-vm-desktop-daemon-idle-e2e.sh "${NVPN_MACOS_SSH_HOST:-}"
      else
        echo "Skipping macOS daemon idle CPU gate because its isolated VM is unreachable."
      fi
      return
      ;;
    local)
      echo "NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU=local is forbidden: release verification never installs a daemon on its host." >&2
      return 2
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU=$mode" >&2
      return 2
      ;;
  esac
}

release_gate_has_physical_ios_device() {
  local requested="${NVPN_IOS_DEVICE:-${NVPN_IOS_DEVICE_ID:-}}"
  [[ "$(uname -s)" == "Darwin" ]] || return 1
  if [[ -n "$requested" ]]; then
    xcrun devicectl device info details \
      --device "$requested" \
      --timeout 5 \
      --quiet >/dev/null 2>&1
    return
  fi
  xcrun xcdevice list --timeout 5 2>/dev/null | python3 -c '
import json
import sys

devices = json.load(sys.stdin)
raise SystemExit(
    0 if any(
        item.get("available") is True
        and item.get("simulator") is False
        and item.get("platform") == "com.apple.platform.iphoneos"
        for item in devices
    ) else 1
)
'
}

run_mobile_idle_cpu_gates() {
  case "$NVPN_IDLE_CPU_GATE" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping mobile idle CPU gates because NVPN_IDLE_CPU_GATE=$NVPN_IDLE_CPU_GATE"
      return
      ;;
  esac

  # Android Release idle is sampled after the first real signed-app network
  # cycle. Simulator/debug idle runs belong to development smoke, not release.
  local ios_device="${NVPN_IOS_DEVICE:-${NVPN_IOS_DEVICE_ID:-}}"
  local ios_smoke_command=(./scripts/mobile-ios-smoke.sh device)
  if [[ -n "$ios_device" ]]; then
    ios_smoke_command+=(--device "$ios_device")
  fi
  ios_smoke_command+=(--install --create-network --vpn-cycle)
  if release_gate_has_physical_ios_device || [[ -n "$ios_device" ]]; then
    release_gate_run_with_timeout "iOS packet tunnel idle CPU" "$IOS_TUNNEL_IDLE_CPU_TIMEOUT_SECS" \
      env \
        NVPN_IOS_RUST_PROFILE=release \
        NVPN_IOS_IDLE_CPU_MAX_PERCENT="${NVPN_IOS_PACKET_TUNNEL_IDLE_CPU_MAX_PERCENT:-$NVPN_IDLE_CPU_MAX_PERCENT}" \
        NVPN_IOS_IDLE_CPU_SETTLE_SECONDS="${NVPN_IOS_PACKET_TUNNEL_IDLE_CPU_SETTLE_SECONDS:-15}" \
        NVPN_IOS_IDLE_CPU_SAMPLE_SECONDS="${NVPN_IOS_PACKET_TUNNEL_IDLE_CPU_SAMPLE_SECONDS:-60}" \
        "${ios_smoke_command[@]}"
    MOBILE_IOS_APP_READY=1
  else
    echo "Skipping iOS packet tunnel idle CPU gate because no physical device is online."
  fi
}

run_mobile_wireguard_exit_gates() {
  local mode="${NVPN_RELEASE_GATE_MOBILE_WG_EXIT_E2E:-auto}"
  local remote_native=0
  if [[ -n "${NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST:-}" \
    && "${NVPN_MOBILE_WG_EXIT_REMOTE_MODE:-native}" == "native" ]]
  then
    remote_native=1
  fi
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping mobile WireGuard exit e2e because NVPN_RELEASE_GATE_MOBILE_WG_EXIT_E2E=$mode"
      return
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|required)
      ;;
    auto|AUTO|Auto|"")
      if [[ "$(uname -s)" != "Darwin" ]] \
        || { [[ "$remote_native" -eq 0 ]] \
          && ! command -v docker >/dev/null 2>&1; } \
        || ! command -v wg >/dev/null 2>&1 \
        || ! command -v adb >/dev/null 2>&1 \
        || ! adb devices 2>/dev/null | awk 'NR > 1 && $2 == "device" && $1 !~ /^emulator-/ { found = 1 } END { exit !found }' \
        || ! release_gate_has_physical_ios_device
      then
        echo "Skipping mobile WireGuard exit e2e because both physical mobile devices and the local fixture tools are not available."
        return
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MOBILE_WG_EXIT_E2E=$mode" >&2
      exit 2
      ;;
  esac

  local evidence_dir android_artifact_dir ios_artifact_dir
  evidence_dir="$RELEASE_GATE_PARALLEL_LOG_DIR/mobile-network"
  android_artifact_dir="$evidence_dir/android-wireguard-dns-artifacts"
  ios_artifact_dir="$evidence_dir/ios-wireguard-dns-artifacts"
  rm -rf "$android_artifact_dir" "$ios_artifact_dir"
  mkdir -p "$android_artifact_dir" "$ios_artifact_dir"

  local image="${NVPN_MOBILE_WG_EXIT_IMAGE:-nostr-vpn-mobile-wireguard-exit-e2e}"
  local image_ready=0
  if [[ "$remote_native" -eq 0 ]]; then
    docker build -q \
      -f "$ROOT_DIR/Dockerfile.mobile-wireguard-exit-e2e" \
      -t "$image" \
      "$ROOT_DIR" >/dev/null
    image_ready=1
  fi

  local port_base="$((53000 + $$ % 1000 * 2))"
  local lanes=()
  release_gate_parallel_start \
    "Android physical WireGuard exit and DNS" \
    release_gate_run_with_timeout \
    "Android physical WireGuard exit and DNS" \
    "$MOBILE_WG_EXIT_TIMEOUT_SECS" \
    env NVPN_IDLE_CPU_GATE="$NVPN_IDLE_CPU_GATE" \
      NVPN_MOBILE_WG_EXIT_DIRECT_HOST=example.com \
      NVPN_MOBILE_WG_EXIT_DIRECT_URL=https://example.com/ \
      NVPN_MOBILE_WG_EXIT_DNS_CASES=automatic-profile,cloudflare-doh,quad9-doh,custom-doh,through-exit \
      NVPN_MOBILE_WG_EXIT_EXPECTED_SOURCE_IP= \
      NVPN_MOBILE_WG_EXIT_LIFECYCLE_GATE=0 \
      NVPN_MOBILE_WG_EXIT_RELEASE_BLACKBOX=1 \
      NVPN_MOBILE_WG_EXIT_SOURCE_IP_URL=https://api.ipify.org \
      NVPN_MOBILE_WG_EXIT_IMAGE_READY="$image_ready" \
      NVPN_MOBILE_WG_EXIT_IMAGE="$image" \
      NVPN_MOBILE_WG_EXIT_REUSE_ANDROID_BUILD=0 \
      NVPN_MOBILE_WG_EXIT_CONTAINER="nostr-vpn-mobile-wg-release-android-$$" \
      NVPN_MOBILE_WG_EXIT_HOST_PORT="$port_base" \
      NVPN_MOBILE_WG_EXIT_SERVER_IP=10.99.77.1 \
      NVPN_MOBILE_WG_EXIT_CLIENT_IP=10.99.77.2 \
      NVPN_MOBILE_WG_EXIT_THROUGH_DNS_IP=10.99.77.53 \
      NVPN_MOBILE_WG_EXIT_HTTP_PROBE_PORT="$port_base" \
      NVPN_ANDROID_DEBUG_RELEASE_SIGNING=1 \
      NVPN_ANDROID_IDLE_CPU_MAX_PERCENT="$ANDROID_RELEASE_FOREGROUND_IDLE_CPU_MAX_PERCENT" \
      NVPN_ANDROID_IDLE_CPU_SAMPLE_SECONDS="$ANDROID_RELEASE_FOREGROUND_IDLE_CPU_SAMPLE_SECONDS" \
      NVPN_ANDROID_IDLE_CPU_OUTPUT="$evidence_dir/android-release-foreground-vpn-off-idle/idle-cpu.json" \
      NVPN_MOBILE_WG_EXIT_INSTALL_ANDROID="$((1 - MOBILE_ANDROID_APP_READY))" \
      NVPN_ANDROID_RESULT_DIR="$android_artifact_dir" \
      NVPN_MOBILE_ANDROID_NETWORK_EVIDENCE_OUTPUT="$evidence_dir/android-wireguard-dns.json" \
      ./scripts/mobile-wireguard-exit-e2e.sh android
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_start \
    "iOS physical WireGuard exit and DNS" \
    release_gate_run_with_timeout \
    "iOS physical WireGuard exit and DNS" \
    "$MOBILE_WG_EXIT_TIMEOUT_SECS" \
    env NVPN_IDLE_CPU_GATE=0 \
      NVPN_MOBILE_WG_EXIT_DIRECT_HOST=example.com \
      NVPN_MOBILE_WG_EXIT_DIRECT_URL=https://example.com/ \
      NVPN_MOBILE_WG_EXIT_DNS_CASES=automatic-profile,cloudflare-doh,quad9-doh,custom-doh,through-exit \
      NVPN_MOBILE_WG_EXIT_EXPECTED_SOURCE_IP= \
      NVPN_MOBILE_WG_EXIT_LIFECYCLE_GATE=0 \
      NVPN_MOBILE_WG_EXIT_RELEASE_BLACKBOX=1 \
      NVPN_MOBILE_WG_EXIT_SOURCE_IP_URL=https://api.ipify.org \
      NVPN_MOBILE_WG_EXIT_IMAGE_READY="$image_ready" \
      NVPN_MOBILE_WG_EXIT_IMAGE="$image" \
      NVPN_MOBILE_WG_EXIT_REUSE_IOS_BUILD=0 \
      NVPN_MOBILE_WG_EXIT_CONTAINER="nostr-vpn-mobile-wg-release-ios-$$" \
      NVPN_MOBILE_WG_EXIT_HOST_PORT="$((port_base + 1))" \
      NVPN_MOBILE_WG_EXIT_SERVER_IP=10.99.78.1 \
      NVPN_MOBILE_WG_EXIT_CLIENT_IP=10.99.78.2 \
      NVPN_MOBILE_WG_EXIT_THROUGH_DNS_IP=10.99.78.53 \
      NVPN_MOBILE_WG_EXIT_HTTP_PROBE_PORT="$((port_base + 1))" \
      NVPN_MOBILE_WG_EXIT_INSTALL_IOS="$((1 - MOBILE_IOS_APP_READY))" \
      NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR="$ios_artifact_dir" \
      NVPN_MOBILE_IOS_NETWORK_EVIDENCE_OUTPUT="$evidence_dir/ios-wireguard-dns.json" \
      ./scripts/mobile-wireguard-exit-e2e.sh ios
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_wait_group "${lanes[@]}"
  MOBILE_ANDROID_APP_READY=1
  MOBILE_IOS_APP_READY=1
}

verify_paid_exit_seller_ui_gates() {
  local app_sha app_tree output
  app_sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  app_tree="$(git -C "$ROOT_DIR" rev-parse 'HEAD^{tree}')"
  output="$RELEASE_GATE_PARALLEL_LOG_DIR/paid-exit-seller-ui/summary.json"
  python3 "$ROOT_DIR/scripts/verify-paid-exit-seller-ui-receipts.py" \
    --app-git-sha "$app_sha" \
    --app-git-tree "$app_tree" \
    --output "$output" \
    "linux=$RELEASE_GATE_PARALLEL_LOG_DIR/paid-exit-seller-ui/linux/receipt.json" \
    "macos=$RELEASE_GATE_PARALLEL_LOG_DIR/desktop-dns-ui/macos/cases/paid-exit-seller.json"
}

run_mobile_underlay_change_gates() {
  local mode="${NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E:-auto}"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping physical mobile underlay-change e2e because NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E=$mode"
      return
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|required)
      ;;
    auto|AUTO|Auto|"")
      if [[ -z "${NVPN_MOBILE_WG_EXIT_HOST_IP:-}" ]]; then
        echo "Skipping physical mobile Wi-Fi radio off/on e2e because its reachable fixture address is not configured."
        return
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E=$mode" >&2
      return 2
      ;;
  esac
  local remote_native=0
  if [[ -n "${NVPN_MOBILE_WG_EXIT_FIXTURE_SSH_HOST:-}" \
    && "${NVPN_MOBILE_WG_EXIT_REMOTE_MODE:-native}" == "native" ]]
  then
    remote_native=1
  fi
  if [[ "$(uname -s)" != "Darwin" ]] \
    || ! command -v wg >/dev/null 2>&1 \
    || ! command -v adb >/dev/null 2>&1 \
    || ! adb devices 2>/dev/null | awk '
      NR > 1 && $2 == "device" && $1 !~ /^emulator-/ { found = 1 }
      END { exit !found }
    ' \
    || ! release_gate_has_physical_ios_device
  then
    echo "Physical mobile underlay-change e2e requires both unlocked phones, WireGuard tools, and adb." >&2
    return 1
  fi
  if [[ "$remote_native" -eq 0 ]] && ! command -v docker >/dev/null 2>&1; then
    echo "Physical mobile underlay-change local/Docker fixture requires Docker." >&2
    return 1
  fi

  local evidence_dir android_artifact_dir ios_artifact_dir
  evidence_dir="$RELEASE_GATE_PARALLEL_LOG_DIR/mobile-network"
  android_artifact_dir="$evidence_dir/android-underlay-lifecycle-artifacts"
  ios_artifact_dir="$evidence_dir/ios-underlay-lifecycle-artifacts"
  rm -rf "$android_artifact_dir" "$ios_artifact_dir"
  mkdir -p "$android_artifact_dir" "$ios_artifact_dir"

  local image="${NVPN_MOBILE_WG_EXIT_IMAGE:-nostr-vpn-mobile-wireguard-exit-e2e}"
  local image_ready=0
  if [[ "$remote_native" -eq 0 ]]; then
    docker build -q \
      -f "$ROOT_DIR/Dockerfile.mobile-wireguard-exit-e2e" \
      -t "$image" \
      "$ROOT_DIR" >/dev/null
    image_ready=1
  fi
  local port_base="$((55000 + $$ % 500 * 2))"

  # Keep each phone's physical radio mutation isolated from every other phone
  # lane so cleanup always restores the original validated Wi-Fi.
  release_gate_run_with_timeout \
    "Android physical Wi-Fi radio off/on recovery" \
    "$MOBILE_WG_EXIT_TIMEOUT_SECS" \
    env NVPN_IDLE_CPU_GATE=0 \
      NVPN_ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS=10 \
      NVPN_ANDROID_LIFECYCLE_CYCLES=1 \
      NVPN_IOS_ACTIVE_TUNNEL_LIFECYCLE_CYCLES=1 \
      NVPN_IOS_RELEASE_NETWORK_BACKGROUND_DWELL_SECS=20 \
      NVPN_MOBILE_UNDERLAY_ASSOCIATION_TIMEOUT_SECS=30 \
      NVPN_MOBILE_UNDERLAY_RECOVERY_MAX_MS=4000 \
      NVPN_MOBILE_WG_EXIT_DIRECT_HOST=example.com \
      NVPN_MOBILE_WG_EXIT_DIRECT_URL=https://example.com/ \
      NVPN_MOBILE_WG_EXIT_DNS_CASES=automatic-profile \
      NVPN_MOBILE_WG_EXIT_EXPECTED_SOURCE_IP= \
      NVPN_MOBILE_WG_EXIT_LIFECYCLE_GATE=1 \
      NVPN_MOBILE_WG_EXIT_RELEASE_BLACKBOX=1 \
      NVPN_MOBILE_WG_EXIT_SOURCE_IP_URL=https://api.ipify.org \
      NVPN_MOBILE_WG_EXIT_UNDERLAY_CHANGE_GATE=1 \
      NVPN_MOBILE_WG_EXIT_IMAGE_READY="$image_ready" \
      NVPN_MOBILE_WG_EXIT_IMAGE="$image" \
      NVPN_MOBILE_WG_EXIT_CONTAINER="nostr-vpn-mobile-underlay-android-$$" \
      NVPN_MOBILE_WG_EXIT_HOST_PORT="$port_base" \
      NVPN_MOBILE_WG_EXIT_SERVER_IP=10.99.79.1 \
      NVPN_MOBILE_WG_EXIT_CLIENT_IP=10.99.79.2 \
      NVPN_MOBILE_WG_EXIT_THROUGH_DNS_IP=10.99.79.53 \
      NVPN_MOBILE_WG_EXIT_HTTP_PROBE_PORT="$port_base" \
      NVPN_ANDROID_DEBUG_RELEASE_SIGNING=1 \
      NVPN_MOBILE_WG_EXIT_REUSE_ANDROID_BUILD=1 \
      NVPN_MOBILE_WG_EXIT_INSTALL_ANDROID="$((1 - MOBILE_ANDROID_APP_READY))" \
      NVPN_ANDROID_RESULT_DIR="$android_artifact_dir" \
      NVPN_MOBILE_ANDROID_NETWORK_EVIDENCE_OUTPUT="$evidence_dir/android-underlay-lifecycle.json" \
      ./scripts/mobile-wireguard-exit-e2e.sh android
  MOBILE_ANDROID_APP_READY=1

  release_gate_run_with_timeout \
    "iOS physical Wi-Fi radio off/on recovery" \
    "$MOBILE_WG_EXIT_TIMEOUT_SECS" \
    env NVPN_IDLE_CPU_GATE=0 \
      NVPN_ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS=10 \
      NVPN_ANDROID_LIFECYCLE_CYCLES=1 \
      NVPN_IOS_ACTIVE_TUNNEL_LIFECYCLE_CYCLES=1 \
      NVPN_IOS_RELEASE_NETWORK_BACKGROUND_DWELL_SECS=20 \
      NVPN_MOBILE_UNDERLAY_ASSOCIATION_TIMEOUT_SECS=30 \
      NVPN_MOBILE_UNDERLAY_RECOVERY_MAX_MS=4000 \
      NVPN_MOBILE_WG_EXIT_DIRECT_HOST=example.com \
      NVPN_MOBILE_WG_EXIT_DIRECT_URL=https://example.com/ \
      NVPN_MOBILE_WG_EXIT_DNS_CASES=automatic-profile \
      NVPN_MOBILE_WG_EXIT_EXPECTED_SOURCE_IP= \
      NVPN_MOBILE_WG_EXIT_LIFECYCLE_GATE=1 \
      NVPN_MOBILE_WG_EXIT_RELEASE_BLACKBOX=1 \
      NVPN_MOBILE_WG_EXIT_SOURCE_IP_URL=https://api.ipify.org \
      NVPN_MOBILE_WG_EXIT_UNDERLAY_CHANGE_GATE=1 \
      NVPN_MOBILE_WG_EXIT_IMAGE_READY="$image_ready" \
      NVPN_MOBILE_WG_EXIT_IMAGE="$image" \
      NVPN_MOBILE_WG_EXIT_CONTAINER="nostr-vpn-mobile-underlay-ios-$$" \
      NVPN_MOBILE_WG_EXIT_HOST_PORT="$((port_base + 1))" \
      NVPN_MOBILE_WG_EXIT_SERVER_IP=10.99.80.1 \
      NVPN_MOBILE_WG_EXIT_CLIENT_IP=10.99.80.2 \
      NVPN_MOBILE_WG_EXIT_THROUGH_DNS_IP=10.99.80.53 \
      NVPN_MOBILE_WG_EXIT_HTTP_PROBE_PORT="$((port_base + 1))" \
      NVPN_MOBILE_WG_EXIT_REUSE_IOS_BUILD=1 \
      NVPN_MOBILE_WG_EXIT_INSTALL_IOS="$((1 - MOBILE_IOS_APP_READY))" \
      NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR="$ios_artifact_dir" \
      NVPN_MOBILE_IOS_NETWORK_EVIDENCE_OUTPUT="$evidence_dir/ios-underlay-lifecycle.json" \
      ./scripts/mobile-wireguard-exit-e2e.sh ios
  MOBILE_IOS_APP_READY=1
}

run_android_legacy_replacement_gate() {
  local mode="${NVPN_RELEASE_GATE_ANDROID_LEGACY_REPLACEMENT_E2E:-auto}"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Android legacy-package replacement e2e because NVPN_RELEASE_GATE_ANDROID_LEGACY_REPLACEMENT_E2E=$mode"
      return
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On)
      ;;
    auto|AUTO|Auto|"")
      if ! command -v adb >/dev/null 2>&1 \
        || ! adb devices 2>/dev/null | awk '
          NR > 1 && $2 == "device" && $1 !~ /^emulator-/ { found = 1 }
          END { exit !found }
        '
      then
        echo "Skipping Android legacy-package replacement e2e because no physical device is online."
        return
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_ANDROID_LEGACY_REPLACEMENT_E2E=$mode" >&2
      return 2
      ;;
  esac

  release_gate_run_with_timeout \
    "Android legacy-package replacement e2e" \
    "$ANDROID_LEGACY_REPLACEMENT_TIMEOUT_SECS" \
    env NVPN_ANDROID_DEBUG_RELEASE_SIGNING=1 \
    NVPN_ANDROID_LEGACY_REUSE_CANONICAL_APK="$MOBILE_ANDROID_APP_READY" \
    NVPN_ANDROID_LEGACY_CANONICAL_APK="$ROOT_DIR/android/app/build/outputs/apk/release/app-release.apk" \
    NVPN_ANDROID_LEGACY_RESULT_DIR="$RELEASE_GATE_PARALLEL_LOG_DIR/mobile-network/android-replacement-artifacts" \
    ./scripts/mobile-android-legacy-replacement-e2e.sh
  MOBILE_ANDROID_APP_READY=1
}

run_mobile_join_e2e_gate() {
  local mode="${NVPN_RELEASE_GATE_MOBILE_JOIN_E2E:-required}"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping signed Release cross-platform join e2e because NVPN_RELEASE_GATE_MOBILE_JOIN_E2E=$mode"
      return
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|required)
      [[ "$(uname -s)" == "Darwin" ]] \
        || { echo "Required signed Release join gate needs macOS/Xcode." >&2; return 1; }
      command -v adb >/dev/null 2>&1 \
        || { echo "Required signed Release join gate needs adb." >&2; return 1; }
      adb devices 2>/dev/null | awk \
        'NR > 1 && $2 == "device" && $1 !~ /^emulator-/ { found = 1 } END { exit !found }' \
        || { echo "Required signed Release join gate needs a physical Android phone." >&2; return 1; }
      release_gate_has_physical_ios_device \
        || { echo "Required signed Release join gate needs a physical iPhone." >&2; return 1; }
      macos_vm_reachable \
        || { echo "Required signed Release join gate needs the macOS VM." >&2; return 1; }
      ;;
    auto|AUTO|Auto|"")
      if [[ "$(uname -s)" != "Darwin" ]] \
        || ! command -v adb >/dev/null 2>&1 \
        || ! adb devices 2>/dev/null | awk 'NR > 1 && $2 == "device" && $1 !~ /^emulator-/ { found = 1 } END { exit !found }' \
        || ! release_gate_has_physical_ios_device \
        || ! macos_vm_reachable
      then
        echo "Skipping signed Release cross-platform join e2e because its phones or macOS VM are unavailable."
        return
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_MOBILE_JOIN_E2E=$mode" >&2
      exit 2
      ;;
  esac

  local android_result_dir android_receipt android_fips_metadata
  local ios_result_dir ios_derived_data ios_app ios_xctestrun ios_receipt
  local ios_production_receipt
  local ios_fips_metadata release_join_result_dir
  android_result_dir="${NVPN_ANDROID_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-android}"
  android_receipt="${NVPN_MOBILE_ANDROID_RELEASE_RECEIPT:-$android_result_dir/mobile-android-release-artifact.json}"
  android_fips_metadata="${NVPN_ANDROID_FIPS_METADATA_RECEIPT:-$ROOT_DIR/artifacts/mobile-android/fips-linkage.json}"
  ios_result_dir="${NVPN_MOBILE_WG_EXIT_IOS_UI_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-ios}"
  release_join_result_dir="${NVPN_RELEASE_JOIN_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-release-join}"
  ios_derived_data="${NVPN_RELEASE_JOIN_IOS_VARIANT_DERIVED_DATA:-$release_join_result_dir/ios-derived-data}"
  ios_app="${NVPN_RELEASE_JOIN_IOS_VARIANT_APP_PATH:-$ios_derived_data/Build/Products/Release-iphoneos/Nostr VPN.app}"
  ios_production_receipt="${NVPN_MOBILE_IOS_RELEASE_RECEIPT:-$ios_result_dir/mobile-ios-release-artifact.json}"
  ios_receipt="${NVPN_RELEASE_JOIN_IOS_VARIANT_RECEIPT:-$release_join_result_dir/ios-join-test-variant.json}"
  ios_fips_metadata="${NVPN_IOS_FIPS_METADATA_RECEIPT:-$ROOT_DIR/artifacts/mobile-ios/fips-linkage.json}"
  ios_xctestrun="$(
    select_generated_ios_release_xctestrun \
      "$ios_derived_data/Build/Products" \
      "Strict Release join reuse"
  )" || return 1

  release_gate_run_with_timeout \
    "Signed Release public-UI cross-platform join e2e" \
    "$MOBILE_JOIN_E2E_TIMEOUT_SECS" \
    env NVPN_RELEASE_JOIN_ALLOW_ANDROID_DATA_CLEAR=YES \
    NVPN_RELEASE_JOIN_DESKTOP_MOBILE=1 \
    NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1 \
    NVPN_RELEASE_JOIN_ANDROID_APK="$ROOT_DIR/android/app/build/outputs/apk/release/app-release.apk" \
    NVPN_RELEASE_JOIN_ANDROID_RECEIPT="$android_receipt" \
    NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT="$android_fips_metadata" \
    NVPN_RELEASE_JOIN_IOS_DERIVED_DATA="$ios_derived_data" \
    NVPN_RELEASE_JOIN_IOS_APP_PATH="$ios_app" \
    NVPN_RELEASE_JOIN_IOS_XCTESTRUN="$ios_xctestrun" \
    NVPN_RELEASE_JOIN_IOS_RECEIPT="$ios_receipt" \
    NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT="$ios_production_receipt" \
    NVPN_RELEASE_JOIN_IOS_FIPS_METADATA_RECEIPT="$ios_fips_metadata" \
    ./scripts/mobile-release-join-e2e.sh
  MOBILE_ANDROID_APP_READY=1
  MOBILE_IOS_APP_READY=1
}

run_windows_release_mobile_join_e2e_gate() {
  local mode="${NVPN_RELEASE_GATE_WINDOWS_MOBILE_JOIN_E2E:-${NVPN_RELEASE_GATE_MOBILE_JOIN_E2E:-required}}"
  local host="${NVPN_WINDOWS_SSH_HOST:-}"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Windows/Pixel signed Release join e2e because NVPN_RELEASE_GATE_WINDOWS_MOBILE_JOIN_E2E=$mode"
      return
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|required)
      windows_vm_reachable "$host" \
        || { echo "Required Windows/Pixel join VM is unreachable." >&2; return 1; }
      ;;
    auto|AUTO|Auto|"")
      if ! windows_vm_reachable "$host"; then
        echo "Skipping Windows/Pixel signed Release join e2e because its VM is unreachable."
        return
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_WINDOWS_MOBILE_JOIN_E2E=$mode" >&2
      return 2
      ;;
  esac

  local result_dir android_apk android_install_receipt
  local android_result_dir android_receipt android_fips_metadata
  result_dir="${NVPN_RELEASE_JOIN_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-release-join}"
  android_result_dir="${NVPN_ANDROID_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-android}"
  android_receipt="${NVPN_MOBILE_ANDROID_RELEASE_RECEIPT:-$android_result_dir/mobile-android-release-artifact.json}"
  android_fips_metadata="${NVPN_ANDROID_FIPS_METADATA_RECEIPT:-$ROOT_DIR/artifacts/mobile-android/fips-linkage.json}"
  android_apk="$ROOT_DIR/android/app/build/outputs/apk/release/app-release.apk"
  android_install_receipt="$result_dir/android-release-install.json"
  [[ -f "$android_apk" && -f "$android_install_receipt" \
    && -f "$android_receipt" && -f "$android_fips_metadata" ]] || {
    echo "Windows/Pixel join requires the exact APK, artifact/FIPS receipts, and install receipt from the mobile join lane." >&2
    return 1
  }
  release_gate_run_with_timeout \
    "Windows/Pixel signed Release public-UI manual join e2e" \
    "$MOBILE_JOIN_E2E_TIMEOUT_SECS" \
    env \
      NVPN_RELEASE_JOIN_ANDROID_APK="$android_apk" \
      NVPN_RELEASE_JOIN_ANDROID_RECEIPT="$android_receipt" \
      NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT="$android_fips_metadata" \
      NVPN_RELEASE_JOIN_ANDROID_INSTALL_RECEIPT="$android_install_receipt" \
      NVPN_RELEASE_JOIN_RESULT_DIR="$result_dir" \
      ./scripts/windows-vm-release-mobile-join-e2e.sh "$host"
}

run_linux_release_mobile_join_e2e_gate() {
  local mode="${NVPN_RELEASE_GATE_LINUX_MOBILE_JOIN_E2E:-${NVPN_RELEASE_GATE_MOBILE_JOIN_E2E:-required}}"
  local host="${NVPN_UBUNTU_SSH_HOST:-}"
  case "$mode" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Linux/Pixel signed Release join e2e because NVPN_RELEASE_GATE_LINUX_MOBILE_JOIN_E2E=$mode"
      return
      ;;
    1|true|TRUE|True|yes|YES|Yes|on|ON|On|required)
      ubuntu_vm_reachable \
        || { echo "Required Linux/Pixel join VM is unreachable." >&2; return 1; }
      ;;
    auto|AUTO|Auto|"")
      if ! ubuntu_vm_reachable; then
        echo "Skipping Linux/Pixel signed Release join e2e because its VM is unreachable."
        return
      fi
      ;;
    *)
      echo "Unsupported NVPN_RELEASE_GATE_LINUX_MOBILE_JOIN_E2E=$mode" >&2
      return 2
      ;;
  esac

  local result_dir android_result_dir android_receipt android_fips_metadata
  result_dir="${NVPN_RELEASE_JOIN_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-release-join}"
  android_result_dir="${NVPN_ANDROID_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-android}"
  android_receipt="${NVPN_MOBILE_ANDROID_RELEASE_RECEIPT:-$android_result_dir/mobile-android-release-artifact.json}"
  android_fips_metadata="${NVPN_ANDROID_FIPS_METADATA_RECEIPT:-$ROOT_DIR/artifacts/mobile-android/fips-linkage.json}"
  [[ -f "$android_receipt" && -f "$android_fips_metadata" ]] || {
    echo "Linux/Pixel join requires the exact Android artifact and FIPS receipts." >&2
    return 1
  }
  release_gate_run_with_timeout \
    "Linux/Pixel signed Release public-UI manual join e2e" \
    "$MOBILE_JOIN_E2E_TIMEOUT_SECS" \
    env \
      NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1 \
      NVPN_RELEASE_JOIN_ANDROID_APK="$ROOT_DIR/android/app/build/outputs/apk/release/app-release.apk" \
      NVPN_RELEASE_JOIN_ANDROID_RECEIPT="$android_receipt" \
      NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT="$android_fips_metadata" \
      NVPN_RELEASE_JOIN_RESULT_DIR="$result_dir" \
      ./scripts/ubuntu-vm-release-mobile-join-e2e.sh "$host"
}

seal_frozen_ios_release_gate() {
  bool_is_true "${NVPN_RELEASE_IOS_FROZEN_ARCHIVE:-0}" || return 0
  local required_mode release_join_result_dir
  release_join_result_dir="${NVPN_RELEASE_JOIN_RESULT_DIR:-$ROOT_DIR/artifacts/mobile-release-join}"
  for required_mode in \
    NVPN_RELEASE_GATE_MOBILE_WG_EXIT_E2E \
    NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E \
    NVPN_RELEASE_GATE_MOBILE_JOIN_E2E
  do
    bool_is_true "${!required_mode:-}" || {
      echo "Frozen iOS release requires $required_mode=1." >&2
      return 1
    }
  done
  python3 "$ROOT_DIR/scripts/ios_frozen_archive.py" seal-gate \
    --archive-receipt "$ROOT_DIR/dist/ios/frozen/archive-receipt.json" \
    --adhoc-receipt "$ROOT_DIR/dist/ios/frozen/release-testing-receipt.json" \
    --mobile-receipt "$NVPN_MOBILE_IOS_RELEASE_RECEIPT" \
    --mobile-join-ios-variant-receipt \
      "${NVPN_RELEASE_JOIN_IOS_VARIANT_RECEIPT:-$release_join_result_dir/ios-join-test-variant.json}" \
    --mobile-join-receipt "$release_join_result_dir/summary.json" \
    --mobile-wg-receipt "$RELEASE_GATE_PARALLEL_LOG_DIR/mobile-network/ios-wireguard-dns.json" \
    --mobile-underlay-receipt "$RELEASE_GATE_PARALLEL_LOG_DIR/mobile-network/ios-underlay-lifecycle.json" \
    --desktop-mobile-join-receipt "$release_join_result_dir/macos/summary.json" \
    --sealed-mobile-receipt "$ROOT_DIR/dist/ios/frozen/physical-mobile-receipt.json" \
    --output "$ROOT_DIR/dist/ios/frozen/physical-gate-seal.json" \
    --required-gate wireguard-exit-and-five-dns-policies \
    --required-gate background-foreground-and-rapid-start-stop \
    --required-gate wifi-radio-off-on-recovery \
    --required-gate bidirectional-mobile-qr-and-manual-join \
    --required-gate desktop-mobile-manual-join
  echo "Sealed the real-device gates to the frozen iOS archive."
}

docker_release_gates_enabled() {
  ! release_gate_mode_disabled "${NVPN_RELEASE_GATE_DOCKER_E2E:-1}"
}

build_release_gate_docker_node_image() {
  docker compose \
    -p nostr-vpn-release-gate-image \
    -f "$ROOT_DIR/docker-compose.e2e.yml" \
    build node-a
}

build_release_gate_paid_exit_image() {
  local git_common_dir primary_checkout_parent image auto_image
  git_common_dir="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir)"
  primary_checkout_parent="$(dirname "$(dirname "$git_common_dir")")"
  image="${NVPN_RELEASE_GATE_PAID_EXIT_IMAGE:-nostr-vpn-release-gate-paid-exit-node}"
  auto_image="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_IMAGE:-$image}"

  env \
    COMPOSE_PROFILES=paid-exit \
    NVPN_EXIT_NODE_E2E_DOCKERFILE=Dockerfile.paid-exit-e2e \
    NVPN_EXIT_NODE_E2E_IMAGE="$image" \
    NVPN_CASHU_SERVICE_REPO_PATH="${NVPN_CASHU_SERVICE_REPO_PATH:-$primary_checkout_parent/cashu-service}" \
    NVPN_CASHU_SPILMAN_CHANNELS_REPO_PATH="${NVPN_CASHU_SPILMAN_CHANNELS_REPO_PATH:-$primary_checkout_parent/cashu_spilman_channels}" \
    docker compose \
      -p nostr-vpn-release-gate-paid-exit-image \
      -f "$ROOT_DIR/docker-compose.exit-node-e2e.yml" \
      build node-a
  if [[ "$auto_image" != "$image" ]]; then
    docker image tag "$image" "$auto_image"
  fi
}

build_release_gate_web_image() {
  local image startos_image umbrel_image
  image="${NVPN_RELEASE_GATE_WEB_IMAGE:-nostr-vpn-release-gate-web}"
  startos_image="${NVPN_RELEASE_GATE_WEB_STARTOS_IMAGE:-$image}"
  umbrel_image="${NVPN_RELEASE_GATE_UMBREL_IMAGE:-$image}"

  docker build -f "$ROOT_DIR/umbrel/Dockerfile" -t "$image" "$ROOT_DIR"
  if [[ "$startos_image" != "$image" ]]; then
    docker image tag "$image" "$startos_image"
  fi
  if [[ "$umbrel_image" != "$image" && "$umbrel_image" != "$startos_image" ]]; then
    docker image tag "$image" "$umbrel_image"
  fi
}

run_docker_signal_gates() {
  if ! docker_release_gates_enabled; then
    echo "Skipping Docker e2e because NVPN_RELEASE_GATE_DOCKER_E2E=${NVPN_RELEASE_GATE_DOCKER_E2E}"
    return
  fi

  # The standalone topology test keeps its longer soak default. The release
  # gate needs a short continuity assertion here because roaming, loaded
  # liveness, and idle CPU each get dedicated longer measurements below.
  NVPN_E2E_CONTINUITY_SECS="${NVPN_RELEASE_GATE_CONTINUITY_SECS:-15}" \
    NVPN_FIPS_NOSTR_DISCOVERY_POLICY="${NVPN_FIPS_ROUTED_UDP_DISCOVERY_POLICY:-open}" \
    ./scripts/e2e-fips-routed-udp-docker.sh
  NVPN_FIPS_NOSTR_DISCOVERY_POLICY="${NVPN_FIPS_NOSTR_DISCOVERY_POLICY:-configured_only}" \
    ./scripts/e2e-fips-roaming-docker.sh
}

run_mobile_qr_join_latency_gate() {
  if release_gate_mode_disabled "${NVPN_RELEASE_GATE_QR_JOIN_LATENCY:-1}"; then
    echo "Skipping mobile QR-join latency gate on this uncalibrated host."
    return 0
  fi
  # These real public-WebSocket tests use timing ceilings and intentionally
  # interrupt/restart a tunnel. Run them together only after build contention
  # has ended so their delivery and durable-retry measurements remain useful.
  release_cargo_test_filter nostr-vpn-app-core \
    websocket_seed_router_routes_new_recipient_without_preconverged_roster_peer
  release_cargo_test_filter nostr-vpn-app-core \
    websocket_seed_router_retries_durable_join_receipt_after_first_route_failure
  release_cargo_test_filter nostr-vpn-app-core \
    websocket_seed_router_delivers_durable_join_receipt_after_tunnel_restart
}

run_public_fips_transit_gate() {
  release_cargo test "${release_cargo_lock_args[@]}" \
    -p nostr-vpn-core \
    --test fips_public_transit \
    public_transit_routes_fips_control_by_npub_without_direct_peer_config \
    -- \
    --ignored \
    --test-threads=1
}

run_userspace_wireguard_exit_docker_gate() {
  # The kernel and userspace fixtures use the same Compose topology. Give the
  # userspace copy its own benchmark-network subnets so Docker can create both
  # projects concurrently without overlapping IPAM pools.
  env \
    NVPN_WG_EXIT_INTERNET_SUBNET="${NVPN_WG_EXIT_USERSPACE_INTERNET_SUBNET:-198.19.243.0/24}" \
    NVPN_WG_EXIT_PUBLIC_SUBNET="${NVPN_WG_EXIT_USERSPACE_PUBLIC_SUBNET:-198.19.244.0/24}" \
    NVPN_WG_EXIT_UPSTREAM_IP="${NVPN_WG_EXIT_USERSPACE_UPSTREAM_IP:-198.19.243.20}" \
    NVPN_WG_EXIT_UPSTREAM_PUBLIC_IP="${NVPN_WG_EXIT_USERSPACE_UPSTREAM_PUBLIC_IP:-198.19.244.20}" \
    NVPN_WG_EXIT_NODE_A_IP="${NVPN_WG_EXIT_USERSPACE_NODE_A_IP:-198.19.243.10}" \
    NVPN_WG_EXIT_NODE_B_IP="${NVPN_WG_EXIT_USERSPACE_NODE_B_IP:-198.19.243.11}" \
    NVPN_WG_EXIT_TARGET_IP="${NVPN_WG_EXIT_USERSPACE_TARGET_IP:-198.19.244.100}" \
    ./scripts/e2e-wireguard-exit-userspace-docker.sh
}

run_web_startos_manual_join_docker_gate() {
  env \
    NVPN_WEB_STARTOS_JOIN_IMAGE="${NVPN_RELEASE_GATE_WEB_STARTOS_IMAGE:-${NVPN_RELEASE_GATE_WEB_IMAGE:-nostr-vpn-release-gate-web}}" \
    ./scripts/e2e-web-startos-manual-join-docker.sh
}

run_umbrel_release_gate() {
  local image="${NVPN_RELEASE_GATE_UMBREL_IMAGE:-${NVPN_RELEASE_GATE_WEB_IMAGE:-nostr-vpn-release-gate-web}}"
  pnpm --dir "$ROOT_DIR/web/control-panel" install --frozen-lockfile
  env \
    NOSTR_VPN_IMAGE="$image" \
    NVPN_UMBREL_WEB_E2E_SKIP_BUILD="${NVPN_UMBREL_WEB_E2E_SKIP_BUILD:-1}" \
    NVPN_UMBREL_WEB_E2E_PROJECT="${NVPN_RELEASE_GATE_UMBREL_WEB_PROJECT:-nostr-vpn-release-gate-umbrel-web}" \
    NVPN_UMBREL_WEB_PORT="${NVPN_RELEASE_GATE_UMBREL_WEB_PORT:-38180}" \
    ./scripts/e2e-umbrel-web-docker.sh
  env \
    NOSTR_VPN_IMAGE="$image" \
    NVPN_UMBREL_AUTH_JOIN_SKIP_BUILD=1 \
    NVPN_UMBREL_AUTH_JOIN_PROJECT="${NVPN_RELEASE_GATE_UMBREL_AUTH_PROJECT:-nostr-vpn-release-gate-umbrel-auth}" \
    NVPN_UMBREL_AUTH_JOIN_PROXY_PORT="${NVPN_RELEASE_GATE_UMBREL_PROXY_PORT:-38380}" \
    NVPN_UMBREL_AUTH_JOIN_AUTH_PORT="${NVPN_RELEASE_GATE_UMBREL_AUTH_PORT:-38300}" \
    NVPN_UMBREL_AUTH_JOIN_RPC_PORT="${NVPN_RELEASE_GATE_UMBREL_RPC_PORT:-38301}" \
    ./scripts/e2e-umbrel-auth-join-docker.sh
}

run_docker_isolated_functional_gates() {
  docker_release_gates_enabled || return 0

  local lanes=()
  release_gate_parallel_start "Docker NAT-safe MTU" \
    env NVPN_E2E_CONTINUITY_SECS="${NVPN_RELEASE_GATE_CONTINUITY_SECS:-15}" \
    NVPN_FIPS_NOSTR_DISCOVERY_POLICY="${NVPN_FIPS_NOSTR_DISCOVERY_POLICY:-configured_only}" \
    ./scripts/e2e-fips-nat-safe-mtu-docker.sh
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_start "Docker kernel WireGuard exit" \
    ./scripts/e2e-wireguard-exit-docker.sh
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_start "Docker userspace WireGuard exit" \
    run_userspace_wireguard_exit_docker_gate
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_start "Web/StartOS manual join" \
    run_web_startos_manual_join_docker_gate
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_start "Umbrel authenticated requester join" \
    run_umbrel_release_gate
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_start "Docker Spilman paid exit" \
    env \
    NVPN_EXIT_NODE_E2E_IMAGE="${NVPN_RELEASE_GATE_PAID_EXIT_IMAGE:-nostr-vpn-release-gate-paid-exit-node}" \
    NVPN_EXIT_NODE_E2E_PROJECT_NAME="${NVPN_RELEASE_GATE_PAID_EXIT_PROJECT_NAME:-nostr-vpn-release-gate-paid-exit}" \
    NVPN_E2E_INTERNET_SUBNET="${NVPN_RELEASE_GATE_PAID_EXIT_PUBLIC_SUBNET:-198.19.245.0/24}" \
    NVPN_E2E_INTERNET_TARGET_IP="${NVPN_RELEASE_GATE_PAID_EXIT_TARGET_IP:-198.19.245.100}" \
    NVPN_EXIT_NODE_E2E_PUBLIC_IP="${NVPN_RELEASE_GATE_PAID_EXIT_TARGET_IP:-198.19.245.100}" \
    NVPN_E2E_CASHU_MINT_IP="${NVPN_RELEASE_GATE_PAID_EXIT_MINT_IP:-198.19.245.50}" \
    NVPN_E2E_WG_UPSTREAM_IP="${NVPN_RELEASE_GATE_PAID_EXIT_WG_UPSTREAM_IP:-198.19.245.20}" \
    NVPN_E2E_NODE_A_PUBLIC_IP="${NVPN_RELEASE_GATE_PAID_EXIT_NODE_A_IP:-198.19.245.10}" \
    NVPN_E2E_NAT_B_PUBLIC_IP="${NVPN_RELEASE_GATE_PAID_EXIT_NAT_B_IP:-198.19.245.11}" \
    NVPN_E2E_PRIVATE_B_SUBNET="${NVPN_RELEASE_GATE_PAID_EXIT_PRIVATE_SUBNET:-172.31.245.0/24}" \
    NVPN_E2E_PRIVATE_B_GATEWAY_IP="${NVPN_RELEASE_GATE_PAID_EXIT_PRIVATE_GATEWAY_IP:-172.31.245.1}" \
    NVPN_E2E_NAT_B_PRIVATE_IP="${NVPN_RELEASE_GATE_PAID_EXIT_NAT_B_PRIVATE_IP:-172.31.245.2}" \
    NVPN_E2E_NODE_B_PRIVATE_IP="${NVPN_RELEASE_GATE_PAID_EXIT_NODE_B_PRIVATE_IP:-172.31.245.3}" \
    ./scripts/e2e-paid-exit-docker.sh
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_start "Docker automatic Spilman paid exit" \
    env \
    NVPN_EXIT_NODE_E2E_IMAGE="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_IMAGE:-${NVPN_RELEASE_GATE_PAID_EXIT_IMAGE:-nostr-vpn-release-gate-paid-exit-node}}" \
    NVPN_EXIT_NODE_E2E_PROJECT_NAME="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_PROJECT_NAME:-nostr-vpn-release-gate-paid-exit-auto}" \
    NVPN_E2E_INTERNET_SUBNET="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_PUBLIC_SUBNET:-198.19.246.0/24}" \
    NVPN_E2E_INTERNET_TARGET_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_TARGET_IP:-198.19.246.100}" \
    NVPN_EXIT_NODE_E2E_PUBLIC_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_TARGET_IP:-198.19.246.100}" \
    NVPN_E2E_CASHU_MINT_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_MINT_IP:-198.19.246.50}" \
    NVPN_E2E_WG_UPSTREAM_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_WG_UPSTREAM_IP:-198.19.246.20}" \
    NVPN_E2E_NODE_A_PUBLIC_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_NODE_A_IP:-198.19.246.10}" \
    NVPN_E2E_NAT_B_PUBLIC_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_NAT_B_IP:-198.19.246.11}" \
    NVPN_E2E_PRIVATE_B_SUBNET="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_PRIVATE_SUBNET:-172.31.246.0/24}" \
    NVPN_E2E_PRIVATE_B_GATEWAY_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_PRIVATE_GATEWAY_IP:-172.31.246.1}" \
    NVPN_E2E_NAT_B_PRIVATE_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_NAT_B_PRIVATE_IP:-172.31.246.2}" \
    NVPN_E2E_NODE_B_PRIVATE_IP="${NVPN_RELEASE_GATE_PAID_EXIT_AUTO_NODE_B_PRIVATE_IP:-172.31.246.3}" \
    ./scripts/e2e-paid-exit-automatic-docker.sh
  lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  release_gate_parallel_wait_group "${lanes[@]}"
}

run_docker_perf_gate() {
  docker_release_gates_enabled || return 0
  case "${NVPN_RELEASE_GATE_PERF_E2E:-1}" in
    0|false|FALSE|False|no|NO|No|off|OFF|Off)
      echo "Skipping Docker perf regression e2e because NVPN_RELEASE_GATE_PERF_E2E=${NVPN_RELEASE_GATE_PERF_E2E}"
      ;;
    *)
      local perf_output_dir
      perf_output_dir="$(release_gate_perf_output_dir)"
      echo "Writing Docker nvpn+FIPS perf artifacts to $perf_output_dir"
      NVPN_FIPS_NOSTR_DISCOVERY_POLICY="${NVPN_FIPS_NOSTR_DISCOVERY_POLICY:-configured_only}" \
        NVPN_PERF_OUTPUT_DIR="$perf_output_dir" \
        ./scripts/e2e-fips-perf-regression-docker.sh
      ;;
  esac
}

release_gate_cleanup_private_build_dirs() {
  local result_dir="${NVPN_RELEASE_JOIN_RESULT_DIR:-}"
  local path
  [[ -n "$result_dir" ]] || return 0
  [[ "$result_dir" == /* && "$result_dir" != "/" && ! -L "$result_dir" ]] || {
    echo "Refusing private build cleanup for unsafe release join directory." >&2
    return 1
  }
  [[ ! -e "$result_dir" || -d "$result_dir" ]] || {
    echo "Release join result path is not a directory." >&2
    return 1
  }
  [[ -d "$result_dir" ]] || return 0

  for path in "$result_dir"/.desktop-private-*; do
    [[ -e "$path" || -L "$path" ]] || continue
    [[ -d "$path" && ! -L "$path" ]] || {
      echo "Refusing unexpected private build path: $path" >&2
      return 1
    }
    rm -rf -- "$path"
  done
  for path in "$result_dir"/.desktop-private-*; do
    [[ ! -e "$path" && ! -L "$path" ]] || {
      echo "Private build path survived release-gate cleanup: $path" >&2
      return 1
    }
  done
}

release_gate_cleanup() {
  local status="$?" cleanup_failed=0
  trap - EXIT
  release_gate_parallel_cancel_all || cleanup_failed=1
  if [[ "${LINUX_PLATFORM_LANE_PRE_SYNCED:-0}" == "1" ]] \
    && ubuntu_vm_reachable
  then
    local ROOT="$ROOT_DIR"
    local SSH_HOST="${NVPN_UBUNTU_SSH_HOST:-}"
    local GUEST_SRC_ROOT="${NVPN_UBUNTU_GUEST_SRC_ROOT:-src}"
    local GUEST_REPO="$GUEST_SRC_ROOT/nostr-vpn-release-gate"
    ubuntu_vm_recover_stale_imported_release_bundle || cleanup_failed=1
  fi
  release_gate_cleanup_private_build_dirs || cleanup_failed=1
  restore_release_cargo_lock || cleanup_failed=1
  if [[ "$status" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    status=1
  fi
  exit "$status"
}

main() {
  local started_at
  started_at="$(date +%s)"
  local log_dir="${NVPN_RELEASE_GATE_LOG_DIR:-$ROOT_DIR/artifacts/release-gate-logs/$(date -u +%Y%m%dT%H%M%SZ)}"
  release_gate_parallel_init "$log_dir"
  HOST_LINUX_VM_BUNDLE_PATH_RECEIPT="$log_dir/host-linux-vm-bundle-path.txt"
  export HOST_LINUX_VM_BUNDLE_PATH_RECEIPT
  rm -f "$HOST_LINUX_VM_BUNDLE_PATH_RECEIPT"
  WINDOWS_PLATFORM_PREPARATION_RECEIPT="$log_dir/windows-platform-prepared.txt"
  MACOS_PLATFORM_PREPARATION_RECEIPT="$log_dir/macos-platform-prepared.txt"
  LINUX_PLATFORM_PREPARATION_RECEIPT="$log_dir/linux-platform-prepared.txt"
  export WINDOWS_PLATFORM_PREPARATION_RECEIPT
  export MACOS_PLATFORM_PREPARATION_RECEIPT
  export LINUX_PLATFORM_PREPARATION_RECEIPT
  rm -f \
    "$WINDOWS_PLATFORM_PREPARATION_RECEIPT" \
    "$MACOS_PLATFORM_PREPARATION_RECEIPT" \
    "$LINUX_PLATFORM_PREPARATION_RECEIPT"
  export WINDOWS_LANE_PRE_SYNCED=0
  export MACOS_PLATFORM_LANE_PRE_SYNCED=0
  export LINUX_PLATFORM_LANE_PRE_SYNCED=0
  export NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY=0
  local mobile_artifact_receipt_dir="$log_dir/mobile-release-artifacts"
  mkdir -p "$mobile_artifact_receipt_dir"
  export NVPN_MOBILE_ANDROID_RELEASE_RECEIPT="$mobile_artifact_receipt_dir/android.json"
  export NVPN_MOBILE_IOS_RELEASE_RECEIPT="$mobile_artifact_receipt_dir/ios.json"
  rm -f \
    "$NVPN_MOBILE_ANDROID_RELEASE_RECEIPT" \
    "$NVPN_MOBILE_IOS_RELEASE_RECEIPT"
  trap release_gate_cleanup EXIT

  release_gate_enforce_complete_real_network_modes
  release_gate_require_complete_fixture_inputs
  seal_release_gate_app_candidate

  # Validate generated version metadata before any remote lane snapshots the
  # candidate. The remaining preflight leaves tracked source unchanged and can
  # overlap work on resource-isolated remote hosts.
  run_release_gate_candidate_preflight

  local windows_platform_requested_for_gate=0
  if windows_platform_lane_requested; then
    windows_platform_requested_for_gate=1
    # Seal crates.io/FIPS provenance while the exact candidate is still clean.
    # Later release preparation deliberately realizes a temporary Cargo graph.
    prepare_windows_source_fips_receipt
  fi

  # These preparation lanes read or snapshot the tracked candidate. Join all
  # of them before any Cargo command: an ignored user Cargo patch config can
  # make even a nominally static check realize Cargo.lock. The already-synced
  # VM verification lanes start again below and overlap host validation.
  local platform_preparation_lanes=()
  if [[ "$windows_platform_requested_for_gate" == "1" ]]; then
    release_gate_parallel_start \
      "Windows platform preparation" \
      prepare_windows_platform_lane_sync
    platform_preparation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
  fi

  local macos_platform_requested_for_gate=0
  if macos_platform_lane_requested; then
    macos_platform_requested_for_gate=1
    release_gate_parallel_start \
      "macOS platform preparation" \
      prepare_macos_platform_lane_sync
    platform_preparation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
  fi

  local linux_platform_requested_for_gate=0
  if linux_platform_lane_requested; then
    linux_platform_requested_for_gate=1
    release_gate_parallel_start \
      "Linux platform preparation" \
      prepare_linux_platform_lane_sync
    platform_preparation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
  elif linux_underlay_gate_reachable; then
    release_gate_parallel_start \
      "Linux host-built release bundle" \
      prepare_host_linux_vm_bundle_and_record
    platform_preparation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
  fi

  release_gate_parallel_wait_group "${platform_preparation_lanes[@]}"
  if [[ -e "$WINDOWS_PLATFORM_PREPARATION_RECEIPT" ]]; then
    platform_preparation_receipt_valid \
      "$WINDOWS_PLATFORM_PREPARATION_RECEIPT" windows || {
      echo "Windows platform preparation receipt is invalid." >&2
      return 1
    }
    export WINDOWS_LANE_PRE_SYNCED=1
  fi
  if [[ -e "$MACOS_PLATFORM_PREPARATION_RECEIPT" ]]; then
    platform_preparation_receipt_valid \
      "$MACOS_PLATFORM_PREPARATION_RECEIPT" macos || {
      echo "macOS platform preparation receipt is invalid." >&2
      return 1
    }
    export MACOS_PLATFORM_LANE_PRE_SYNCED=1
    export NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY=1
  fi
  if [[ -e "$LINUX_PLATFORM_PREPARATION_RECEIPT" ]]; then
    platform_preparation_receipt_valid \
      "$LINUX_PLATFORM_PREPARATION_RECEIPT" linux || {
      echo "Linux platform preparation receipt is invalid." >&2
      return 1
    }
    export LINUX_PLATFORM_LANE_PRE_SYNCED=1
  fi
  if [[ -e "$HOST_LINUX_VM_BUNDLE_PATH_RECEIPT" ]]; then
    load_host_linux_vm_bundle_path_receipt
  fi
  prepare_release_cargo_config

  local concurrent_validation_lanes=()
  if [[ "$windows_platform_requested_for_gate" == "1" ]]; then
    release_gate_parallel_start "Windows platform" run_windows_platform_lane
    concurrent_validation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
  fi

  if [[ "$macos_platform_requested_for_gate" == "1" ]]; then
    release_gate_parallel_start "macOS platform UI" run_macos_platform_lane
    concurrent_validation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
  fi

  if [[ "$linux_platform_requested_for_gate" == "1" ]]; then
    release_gate_parallel_start "Linux platform UI" run_linux_platform_lane
    concurrent_validation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
  fi

  # Android static checks do not build Rust, and the Docker builder owns an
  # isolated context/cache. Start both immediately beside the remote platform
  # lanes; host Rust waits until synchronous static checks finish so Cargo
  # commands never race each other over the shared realized lock.
  release_gate_parallel_start \
    "Android compile, unit tests, and lint" \
    run_android_static_validation_lane
  concurrent_validation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  local docker_build_requested=0
  if docker_release_gates_enabled; then
    export NVPN_E2E_NODE_IMAGE="${NVPN_RELEASE_GATE_E2E_NODE_IMAGE:-${NVPN_E2E_NODE_IMAGE:-nostr-vpn-e2e-node}}"
    export NVPN_EXIT_NODE_E2E_IMAGE="$NVPN_E2E_NODE_IMAGE"
    release_gate_parallel_start "Docker node image build" build_release_gate_docker_node_image
    concurrent_validation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
    release_gate_parallel_start "Docker paid-exit image build" build_release_gate_paid_exit_image
    concurrent_validation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
    release_gate_parallel_start "Docker web image build" build_release_gate_web_image
    concurrent_validation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")
    docker_build_requested=1
  fi

  release_gate_parallel_start "Host static and Rust validation" run_host_validation_lane
  concurrent_validation_lanes+=("$RELEASE_GATE_PARALLEL_LAST_INDEX")

  local concurrent_validation_status=0
  release_gate_parallel_wait_group "${concurrent_validation_lanes[@]}" \
    || concurrent_validation_status=$?
  if ((concurrent_validation_status != 0)); then
    return "$concurrent_validation_status"
  fi

  if ((docker_build_requested)); then
    export NVPN_E2E_SKIP_NODE_BUILD=1
    export NVPN_PERF_SKIP_BUILD=1
    export NVPN_EXIT_NODE_E2E_SKIP_BUILD=1
    export NVPN_WEB_STARTOS_JOIN_IMAGE_READY=1
    export NVPN_UMBREL_WEB_E2E_SKIP_BUILD=1
  fi

  # The real desktop network proofs own their target VM and hypervisor
  # topology. Join every parallel UI/build lane before changing links, routes,
  # or entering any latency/performance/device measurement.
  run_desktop_app_launch_smokes
  run_linux_exclusive_desktop_gates
  run_windows_exclusive_desktop_gates
  run_macos_exclusive_desktop_gates

  run_mobile_qr_join_latency_gate
  run_public_fips_transit_gate

  # Routed idle CPU and roaming remain serial. The remaining functional Docker
  # projects have isolated names/subnets and no timing assertions, so overlap
  # them and join before throughput or any host/device measurement begins.
  run_docker_signal_gates
  run_docker_isolated_functional_gates
  run_docker_perf_gate
  ./scripts/release-gate-host-pair-latency.sh
  ./scripts/release-gate-host-pair-loaded-latency.sh

  run_macos_daemon_idle_cpu_gate
  run_mobile_idle_cpu_gates
  run_mobile_wireguard_exit_gates
  verify_paid_exit_seller_ui_gates
  run_android_legacy_replacement_gate
  run_mobile_underlay_change_gates

  # One physical Pixel cannot safely serve multiple admin/joiner drivers at
  # once. Keep these exact-artifact public-UI lanes serial, while reusing the
  # already installed signed APK and host-built desktop artifacts.
  run_mobile_join_e2e_gate
  run_windows_release_mobile_join_e2e_gate
  run_linux_release_mobile_join_e2e_gate
  seal_frozen_ios_release_gate

  local elapsed target_status
  elapsed="$(( $(date +%s) - started_at ))"
  if (( elapsed <= RELEASE_GATE_TARGET_SECS )); then
    target_status="met"
  else
    target_status="missed"
  fi
  printf '{\n  "elapsedSeconds": %d,\n  "targetSeconds": %d,\n  "targetStatus": "%s"\n}\n' \
    "$elapsed" "$RELEASE_GATE_TARGET_SECS" "$target_status" \
    >"$log_dir/release-gate-summary.json"
  printf 'Release gate passed in %ss; %ss target %s. Lane logs and summary: %s\n' \
    "$elapsed" "$RELEASE_GATE_TARGET_SECS" "$target_status" "$log_dir"
}

main "$@"
