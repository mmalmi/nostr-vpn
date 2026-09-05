#!/usr/bin/env bash

DESKTOP_UNDERLAY_SSH_OPTIONS=(
  -o BatchMode=yes
  -o ConnectionAttempts=1
  -o ConnectTimeout=10
  -o ControlMaster=no
  -o ControlPersist=no
  -o ControlPath=none
  -o ServerAliveInterval=2
  -o ServerAliveCountMax=2
)
# Shared import-only Linux peer lifecycle for physical desktop underlay gates.
# The caller supplies ROOT, HYPERVISOR_SSH, ARTIFACT_DIR and fail().

DESKTOP_UNDERLAY_HOST_PEER_BINARY=""
DESKTOP_UNDERLAY_HOST_PEER_SHA256=""
DESKTOP_UNDERLAY_HOST_PEER_SIZE=""
DESKTOP_UNDERLAY_HOST_PEER_REMOTE_DIR=""
DESKTOP_UNDERLAY_HOST_PEER_RUNNER=""
DESKTOP_UNDERLAY_HOST_PEER_IMPORTED=0

desktop_underlay_host_peer_error() {
  echo "desktop underlay host-peer import failed: $*" >&2
}

desktop_underlay_app_version() {
  local manifest="$1"
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
  ' "$manifest"
}

desktop_underlay_assert_app_candidate() {
  local app_sha="$1" app_tree="$2"
  local app_root="${3:-$ROOT}"
  [[ -n "${ROOT:-}" && -f "$ROOT/scripts/release_common.sh" ]] || {
    desktop_underlay_host_peer_error "release checkout validation is unavailable"
    return 1
  }
  # shellcheck disable=SC1091
  source "$ROOT/scripts/release_common.sh" || {
    desktop_underlay_host_peer_error "could not load release checkout validation"
    return 1
  }
  assert_release_checkout_state \
    "$app_root" "$app_sha" "$app_tree" \
    "Desktop underlay host-peer import" || {
      desktop_underlay_host_peer_error \
        "app checkout differs from the exact release candidate"
      return 1
    }
}

desktop_underlay_import_host_peer() {
  [[ -n "${ROOT:-}" && -n "${HYPERVISOR_SSH:-}" && -n "${ARTIFACT_DIR:-}" ]] || {
    desktop_underlay_host_peer_error "ROOT, HYPERVISOR_SSH, and ARTIFACT_DIR are required"
    return 1
  }
  [[ "$(uname -s)" == "Darwin" ]] || {
    desktop_underlay_host_peer_error "Linux peer must be built on the host Mac"
    return 1
  }
  [[ "${NVPN_EXPECTED_APP_GIT_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || {
    desktop_underlay_host_peer_error "exact NVPN_EXPECTED_APP_GIT_SHA is required"
    return 1
  }

  local app_root app_sha app_tree app_version
  local fips_sha fips_tree fips_version target receipt
  local peer_runner peer_runner_sha listener_audit listener_audit_sha remote_dir
  app_root="${NVPN_RELEASE_APP_REPO_PATH:-$ROOT}"
  app_root="$(cd "$app_root" && pwd -P)" || {
    desktop_underlay_host_peer_error "could not resolve release app checkout"
    return 1
  }
  app_sha="$(git -C "$app_root" rev-parse HEAD)" || {
    desktop_underlay_host_peer_error "could not resolve app Git SHA"
    return 1
  }
  app_tree="$(git -C "$app_root" rev-parse 'HEAD^{tree}')" || {
    desktop_underlay_host_peer_error "could not resolve app Git tree"
    return 1
  }
  [[ "$app_sha" == "$NVPN_EXPECTED_APP_GIT_SHA" ]] || {
    desktop_underlay_host_peer_error "app checkout differs from NVPN_EXPECTED_APP_GIT_SHA"
    return 1
  }
  desktop_underlay_assert_app_candidate "$app_sha" "$app_tree" "$app_root" || {
    return 1
  }
  app_version="$(desktop_underlay_app_version "$app_root/Cargo.toml")" || {
    desktop_underlay_host_peer_error "could not read app version"
    return 1
  }
  [[ "$app_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
    desktop_underlay_host_peer_error "could not derive app version"
    return 1
  }

  # This establishes exact FIPS SHA/tree/version globals and independently
  # rejects a dirty or unexpected FIPS checkout before the host build/cache.
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh" || {
    desktop_underlay_host_peer_error "could not load exact FIPS validation"
    return 1
  }
  release_join_require_clean_fips || {
    desktop_underlay_host_peer_error "exact FIPS validation failed"
    return 1
  }
  [[ "${RELEASE_JOIN_FIPS_SHA:-}" =~ ^[0-9a-f]{40}$ \
    && "${RELEASE_JOIN_FIPS_TREE:-}" =~ ^[0-9a-f]{40}$ \
    && "${RELEASE_JOIN_FIPS_VERSION:-}" =~ \
      ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
    desktop_underlay_host_peer_error "exact FIPS validation returned incomplete identity"
    return 1
  }
  fips_sha="$RELEASE_JOIN_FIPS_SHA"
  fips_tree="$RELEASE_JOIN_FIPS_TREE"
  fips_version="$RELEASE_JOIN_FIPS_VERSION"
  target="x86_64-unknown-linux-musl"

  if [[ -n "${NVPN_DESKTOP_UNDERLAY_HOST_PEER_BINARY:-}" ]]; then
    DESKTOP_UNDERLAY_HOST_PEER_BINARY="$NVPN_DESKTOP_UNDERLAY_HOST_PEER_BINARY"
  else
    DESKTOP_UNDERLAY_HOST_PEER_BINARY="$(
      "$app_root/scripts/prepare-macos-release-fips-peer.sh"
    )" || {
      desktop_underlay_host_peer_error "host Linux peer preparation failed"
      return 1
    }
  fi
  [[ "$DESKTOP_UNDERLAY_HOST_PEER_BINARY" == /* \
    && -x "$DESKTOP_UNDERLAY_HOST_PEER_BINARY" ]] || {
    desktop_underlay_host_peer_error "host Linux peer path is invalid"
    return 1
  }
  receipt="$(dirname "$DESKTOP_UNDERLAY_HOST_PEER_BINARY")/receipt.json" || {
    desktop_underlay_host_peer_error "could not derive host Linux peer receipt path"
    return 1
  }
  python3 "$ROOT/scripts/verify-host-linux-peer-artifact.py" \
    "$receipt" \
    "$DESKTOP_UNDERLAY_HOST_PEER_BINARY" \
    "$app_sha" \
    "$app_tree" \
    "$fips_sha" \
    "$fips_tree" \
    "$fips_version" \
    "$target" || {
      desktop_underlay_host_peer_error "host Linux peer receipt verification failed"
      return 1
    }
  file "$DESKTOP_UNDERLAY_HOST_PEER_BINARY" \
    | grep -Eq 'ELF 64-bit.*x86-64' \
    || {
      desktop_underlay_host_peer_error "host-built peer is not x86_64 ELF"
      return 1
    }

  DESKTOP_UNDERLAY_HOST_PEER_SHA256="$(
    shasum -a 256 "$DESKTOP_UNDERLAY_HOST_PEER_BINARY" | awk '{ print $1 }'
  )" || {
    desktop_underlay_host_peer_error "could not hash host Linux peer"
    return 1
  }
  DESKTOP_UNDERLAY_HOST_PEER_SIZE="$(
    stat -f '%z' "$DESKTOP_UNDERLAY_HOST_PEER_BINARY"
  )" || {
    desktop_underlay_host_peer_error "could not size host Linux peer"
    return 1
  }
  [[ "$DESKTOP_UNDERLAY_HOST_PEER_SHA256" =~ ^[0-9a-f]{64}$ \
    && "$DESKTOP_UNDERLAY_HOST_PEER_SIZE" =~ ^[1-9][0-9]*$ ]] || {
    desktop_underlay_host_peer_error "host-built peer has invalid byte receipts"
    return 1
  }
  peer_runner="$ROOT/scripts/desktop-linux-underlay-peer-e2e.sh"
  listener_audit="$ROOT/scripts/lib-desktop-linux-listener-audit.sh"
  [[ -x "$peer_runner" && -f "$listener_audit" ]] || {
    desktop_underlay_host_peer_error "host peer fixture sources are missing"
    return 1
  }
  peer_runner_sha="$(shasum -a 256 "$peer_runner" | awk '{ print $1 }')" || {
    desktop_underlay_host_peer_error "could not hash host peer fixture"
    return 1
  }
  listener_audit_sha="$(
    shasum -a 256 "$listener_audit" | awk '{ print $1 }'
  )" || {
    desktop_underlay_host_peer_error "could not hash host listener audit"
    return 1
  }
  [[ "$peer_runner_sha" =~ ^[0-9a-f]{64}$ \
    && "$listener_audit_sha" =~ ^[0-9a-f]{64}$ ]] || {
    desktop_underlay_host_peer_error "host peer fixture hashes are invalid"
    return 1
  }

  mkdir -p "$ARTIFACT_DIR" || {
    desktop_underlay_host_peer_error "could not create local evidence directory"
    return 1
  }
  cp "$receipt" "$ARTIFACT_DIR/host-peer-local-receipt.json" || {
    desktop_underlay_host_peer_error "could not preserve local host-peer receipt"
    return 1
  }

  remote_dir="$(
    ssh "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" "$HYPERVISOR_SSH" \
      mktemp -d /tmp/nvpn-desktop-underlay-peer.XXXXXX
  )" || {
    desktop_underlay_host_peer_error "could not create remote import directory"
    return 1
  }
  case "$remote_dir" in
    /tmp/nvpn-desktop-underlay-peer.*) ;;
    *)
      desktop_underlay_host_peer_error "Vader returned an unsafe import directory"
      return 1
      ;;
  esac
  DESKTOP_UNDERLAY_HOST_PEER_REMOTE_DIR="$remote_dir"

  scp -q "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" \
    "$DESKTOP_UNDERLAY_HOST_PEER_BINARY" \
    "$HYPERVISOR_SSH:$remote_dir/nvpn.copy" || {
      desktop_underlay_host_peer_error "could not import host Linux peer"
      return 1
    }
  scp -q "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" \
    "$receipt" \
    "$HYPERVISOR_SSH:$remote_dir/receipt.json.copy" || {
      desktop_underlay_host_peer_error "could not import host Linux peer receipt"
      return 1
    }
  scp -q "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" \
    "$peer_runner" \
    "$HYPERVISOR_SSH:$remote_dir/desktop-linux-underlay-peer-e2e.sh.copy" || {
      desktop_underlay_host_peer_error "could not import host peer fixture"
      return 1
    }
  scp -q "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" \
    "$listener_audit" \
    "$HYPERVISOR_SSH:$remote_dir/lib-desktop-linux-listener-audit.sh.copy" || {
      desktop_underlay_host_peer_error "could not import host listener audit"
      return 1
    }

  if ! ssh "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" \
    "$HYPERVISOR_SSH" bash -s -- \
    "$remote_dir" \
    "$DESKTOP_UNDERLAY_HOST_PEER_SHA256" \
    "$DESKTOP_UNDERLAY_HOST_PEER_SIZE" \
    "$app_sha" \
    "$app_tree" \
    "$fips_sha" \
    "$fips_tree" \
    "$fips_version" \
    "$target" \
    "$app_version" \
    "$peer_runner_sha" \
    "$listener_audit_sha" \
    >"$ARTIFACT_DIR/host-peer-remote-version.txt" <<'SH'
set -euo pipefail
remote_dir="$1"
expected_sha="$2"
expected_size="$3"
app_sha="$4"
app_tree="$5"
fips_sha="$6"
fips_tree="$7"
fips_version="$8"
target="$9"
app_version="${10}"
peer_runner_sha="${11}"
listener_audit_sha="${12}"
case "$remote_dir" in
  /tmp/nvpn-desktop-underlay-peer.*) ;;
  *) exit 2 ;;
esac
[[ -d "$remote_dir" && -O "$remote_dir" && ! -L "$remote_dir" ]]
chmod 0700 "$remote_dir"
chmod 0500 "$remote_dir/nvpn.copy"
chmod 0400 "$remote_dir/receipt.json.copy"
chmod 0500 "$remote_dir/desktop-linux-underlay-peer-e2e.sh.copy"
chmod 0400 "$remote_dir/lib-desktop-linux-listener-audit.sh.copy"
[[ "$(sha256sum "$remote_dir/nvpn.copy" | awk '{ print $1 }')" == "$expected_sha" ]]
[[ "$(stat -c '%s' "$remote_dir/nvpn.copy")" == "$expected_size" ]]
[[ "$(
  sha256sum "$remote_dir/desktop-linux-underlay-peer-e2e.sh.copy" \
    | awk '{ print $1 }'
)" == "$peer_runner_sha" ]]
[[ "$(
  sha256sum "$remote_dir/lib-desktop-linux-listener-audit.sh.copy" \
    | awk '{ print $1 }'
)" == "$listener_audit_sha" ]]
file "$remote_dir/nvpn.copy" | grep -Eq 'ELF 64-bit.*x86-64'
jq -e \
  --arg app_sha "$app_sha" \
  --arg app_tree "$app_tree" \
  --arg fips_sha "$fips_sha" \
  --arg fips_tree "$fips_tree" \
  --arg fips_version "$fips_version" \
  --arg target "$target" \
  --arg binary_sha "$expected_sha" \
  --argjson binary_size "$expected_size" \
  '.schema == 1
    and (
      (.builtOnHostMac == true and .builtOnRemoteVm == false)
      or (
        .builtOnHostMac == false
        and .builtOnRemoteVm == true
        and .builtOnMacosUtm == false
        and .buildExecutionHostClass == "remote-linux-builder"
      )
    )
    and .appGitSha == $app_sha
    and .appGitTree == $app_tree
    and .fipsGitSha == $fips_sha
    and .fipsGitTree == $fips_tree
    and .fipsVersion == $fips_version
    and .target == $target
    and .binarySha256 == $binary_sha
    and .binarySize == $binary_size' \
  "$remote_dir/receipt.json.copy" >/dev/null
mv "$remote_dir/nvpn.copy" "$remote_dir/nvpn"
mv "$remote_dir/receipt.json.copy" "$remote_dir/receipt.json"
mv \
  "$remote_dir/desktop-linux-underlay-peer-e2e.sh.copy" \
  "$remote_dir/desktop-linux-underlay-peer-e2e.sh"
mv \
  "$remote_dir/lib-desktop-linux-listener-audit.sh.copy" \
  "$remote_dir/lib-desktop-linux-listener-audit.sh"
short_version="$("$remote_dir/nvpn" --version)"
[[ "$short_version" == "nvpn $app_version" ]]
verbose_version="$("$remote_dir/nvpn" version --verbose)"
printf '%s\n' "$verbose_version" | grep -Fq "(rev ${fips_sha:0:10})"
printf '%s\n%s\n' "$short_version" "$verbose_version"
SH
  then
    desktop_underlay_host_peer_error "remote host-peer verification failed"
    return 1
  fi
  {
    printf 'builtOnHostMac=%s\n' "$(jq -r '.builtOnHostMac' "$receipt")"
    printf 'builtOnRemoteVm=%s\n' "$(jq -r '.builtOnRemoteVm' "$receipt")"
    printf 'buildExecutionHostClass=%s\n' \
      "$(jq -r '.buildExecutionHostClass // "host-macos"' "$receipt")"
    printf 'appVersion=%s\n' "$app_version"
    printf 'appGitSha=%s\n' "$app_sha"
    printf 'appGitTree=%s\n' "$app_tree"
    printf 'fipsGitSha=%s\n' "$fips_sha"
    printf 'fipsGitTree=%s\n' "$fips_tree"
    printf 'fipsVersion=%s\n' "$fips_version"
    printf 'target=%s\n' "$target"
    printf 'binarySha256=%s\n' "$DESKTOP_UNDERLAY_HOST_PEER_SHA256"
    printf 'binarySize=%s\n' "$DESKTOP_UNDERLAY_HOST_PEER_SIZE"
    printf 'peerRunnerSha256=%s\n' "$peer_runner_sha"
    printf 'listenerAuditSha256=%s\n' "$listener_audit_sha"
    printf 'remoteBinary=%s\n' "$remote_dir/nvpn"
    printf 'remotePeerRunner=%s\n' \
      "$remote_dir/desktop-linux-underlay-peer-e2e.sh"
  } >"$ARTIFACT_DIR/host-peer-import-receipt.txt" || {
    desktop_underlay_host_peer_error "could not write host-peer import receipt"
    return 1
  }
  HYPERVISOR_BINARY="$remote_dir/nvpn"
  DESKTOP_UNDERLAY_HOST_PEER_RUNNER="$remote_dir/desktop-linux-underlay-peer-e2e.sh"
  DESKTOP_UNDERLAY_HOST_PEER_IMPORTED=1
}

desktop_underlay_cleanup_host_peer() {
  local remote_dir="${DESKTOP_UNDERLAY_HOST_PEER_REMOTE_DIR:-}"
  [[ -n "$remote_dir" ]] || return 0
  case "$remote_dir" in
    /tmp/nvpn-desktop-underlay-peer.*) ;;
    *)
      echo "refusing unsafe desktop-underlay peer cleanup path: $remote_dir" >&2
      return 1
      ;;
  esac
  if ! perl -e '
    my $seconds = shift @ARGV;
    alarm $seconds;
    exec @ARGV;
    die "exec failed: $!\n";
  ' 30 ssh "${DESKTOP_UNDERLAY_SSH_OPTIONS[@]}" \
    "$HYPERVISOR_SSH" bash -s -- "$remote_dir" <<'SH'
set -euo pipefail
remote_dir="$1"
case "$remote_dir" in
  /tmp/nvpn-desktop-underlay-peer.*) ;;
  *) exit 2 ;;
esac
find "$remote_dir" -xdev -depth -mindepth 1 -delete
rmdir "$remote_dir"
test ! -e "$remote_dir"
SH
  then
    echo "desktop underlay host-peer cleanup failed: remote removal failed" >&2
    return 1
  fi
  mkdir -p "$ARTIFACT_DIR" || {
    echo "desktop underlay host-peer cleanup failed: cannot create evidence directory" >&2
    return 1
  }
  printf 'remote_artifact_removed=true\n' \
    >"$ARTIFACT_DIR/host-peer-cleanup-audit.txt" || {
      echo "desktop underlay host-peer cleanup failed: cannot write removal audit" >&2
      return 1
    }
  DESKTOP_UNDERLAY_HOST_PEER_REMOTE_DIR=""
  DESKTOP_UNDERLAY_HOST_PEER_IMPORTED=0
  HYPERVISOR_BINARY=""
  DESKTOP_UNDERLAY_HOST_PEER_RUNNER=""
}
