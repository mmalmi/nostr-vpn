#!/usr/bin/env bash

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISHER="$ROOT/scripts/publish.sh"

fail() {
  printf 'publish preflight harness failed: %s\n' "$*" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

if grep -Fq 'import tomllib' "$PUBLISHER"; then
  fail "credential preflight requires Python 3.11 tomllib"
fi
if grep -Fq 'url = "https://crates.io/api/v1/me"' "$PUBLISHER"; then
  fail "credential preflight uses the website-only /api/v1/me endpoint"
fi

awk '
  /^preflight_crates_io_credentials\(\) \{/ {
    emit = 1
  }
  /^publish_crate\(\) \{/ {
    exit
  }
  emit {
    print
  }
' "$PUBLISHER" >"$tmp_dir/preflight-function.sh"
grep -Fq 'preflight_crates_io_credentials()' "$tmp_dir/preflight-function.sh" \
  || fail "could not extract credential preflight function"

mkdir -p "$tmp_dir/bin" "$tmp_dir/cargo-home"
cat >"$tmp_dir/bin/cargo" <<'EOF'
#!/bin/bash
set -euo pipefail
[[ "$*" == owner\ --list\ --registry\ crates-io\ * ]] || {
  echo "unexpected cargo arguments" >&2
  exit 64
}
[[ "$*" != *" --token "* ]] || {
  echo "credential leaked onto the command line" >&2
  exit 65
}
printf '%s\n' "$*" >>"$NVPN_TEST_CARGO_LOG"
[[ -n "${CARGO_REGISTRY_TOKEN:-}" || -s "${CARGO_HOME}/credentials.toml" ]] || {
  echo "no token found, please run cargo login" >&2
  exit 101
}
case "${NVPN_TEST_CARGO_MODE:-success}" in
  success)
    printf '%s\n' 'release-owner'
    ;;
  rejected)
    echo "registry query failed" >&2
    exit 101
    ;;
  *)
    echo "unknown test mode" >&2
    exit 66
    ;;
esac
EOF
chmod +x "$tmp_dir/bin/cargo"

cat >"$tmp_dir/cargo-home/credentials.toml" <<'EOF'
[registry]
token = "test-token-from-credentials"
EOF

run_preflight() {
  local mode="$1"
  env -u CARGO_REGISTRY_TOKEN \
    PATH="$tmp_dir/bin:/usr/bin:/bin" \
    CARGO_HOME="$tmp_dir/cargo-home" \
    NVPN_TEST_CARGO_LOG="$tmp_dir/cargo.log" \
    NVPN_TEST_CARGO_MODE="$mode" \
    bash -c '
      source "$1"
      ALL_CRATES=(nostr-vpn-core nostr-vpn-wintun nvpn)
      preflight_crates_io_credentials
    ' bash "$tmp_dir/preflight-function.sh"
}

: >"$tmp_dir/cargo.log"
run_preflight success
[[ "$(wc -l <"$tmp_dir/cargo.log" | tr -d ' ')" == 3 ]] \
  || fail "did not resolve the credential for every publishable crate"
for crate in nostr-vpn-core nostr-vpn-wintun nvpn; do
  grep -Fxq "owner --list --registry crates-io ${crate}" "$tmp_dir/cargo.log" \
    || fail "did not use Cargo's read-only owner query for $crate"
done

if run_preflight rejected >"$tmp_dir/rejected.out" 2>&1; then
  fail "accepted a failed Cargo credential query"
fi

mkdir -p "$tmp_dir/empty-cargo-home"
if env -u CARGO_REGISTRY_TOKEN \
  PATH="$tmp_dir/bin:/usr/bin:/bin" \
  CARGO_HOME="$tmp_dir/empty-cargo-home" \
  NVPN_TEST_CARGO_LOG="$tmp_dir/cargo.log" \
  bash -c '
    source "$1"
    ALL_CRATES=(nostr-vpn-core)
    preflight_crates_io_credentials
  ' bash "$tmp_dir/preflight-function.sh" >"$tmp_dir/missing.out" 2>&1
then
  fail "accepted a missing Cargo credential"
fi
grep -Fq 'Cargo could not resolve crates.io credentials' "$tmp_dir/missing.out" \
  || fail "missing credential error is not actionable"

# Exercise the production preflight with an unpublished dependent. A normal
# package verification would resolve an older registry dependency here.
awk '
  /^verify_dependent_dry_run\(\) \{/ { emit = 1 }
  /^publish_tier\(\) \{/ { exit }
  emit { print }
' "$PUBLISHER" >"$tmp_dir/dependent-function.sh"
awk '
  /^if \[\[ "\$PREFLIGHT_ONLY" -eq 1 \]\]; then/ { emit = 1 }
  emit { print }
  emit && /^fi$/ { exit }
' "$PUBLISHER" >"$tmp_dir/package-preflight.sh"
[[ -s "$tmp_dir/package-preflight.sh" ]] || fail "could not extract package preflight"

cat >"$tmp_dir/bin/cargo" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >>"$NVPN_TEST_CARGO_LOG"
case "$*" in
  'package --locked -p nostr-vpn-core'|'package --locked -p nostr-vpn-wintun') ;;
  'package --locked -p nvpn --list')
    [[ "$NVPN_TEST_CARGO_MODE" != package-failure ]] || exit 71
    ;;
  'check --locked -p nvpn')
    [[ "$NVPN_TEST_CARGO_MODE" != build-failure ]] || exit 72
    ;;
  *)
    echo "dependent registry package is unavailable before its dependency is published" >&2
    exit 73
    ;;
esac
EOF
chmod +x "$tmp_dir/bin/cargo"

run_package_preflight() {
  env PATH="$tmp_dir/bin:/usr/bin:/bin" \
    NVPN_TEST_CARGO_LOG="$tmp_dir/package-cargo.log" \
    NVPN_TEST_CARGO_MODE="$1" \
    bash -c '
      set -euo pipefail
      source "$1"
      PREFLIGHT_ONLY=1
      DRY_RUN=""
      FAILED_CRATES=()
      TIER_1_CRATES=(nostr-vpn-core nostr-vpn-wintun)
      TIER_2_CRATES=(nvpn)
      preflight_crates_io_credentials() { :; }
      verify_exact_release_source() { :; }
      package_crate_and_bind_digest() { cargo package --locked -p "$1"; }
      source "$2"
    ' bash "$tmp_dir/dependent-function.sh" "$tmp_dir/package-preflight.sh"
}

: >"$tmp_dir/package-cargo.log"
run_package_preflight success \
  || fail "preflight tried to package a dependent before its registry dependency exists"
for command in \
  'package --locked -p nostr-vpn-core' \
  'package --locked -p nostr-vpn-wintun' \
  'package --locked -p nvpn --list' \
  'check --locked -p nvpn'
do
  grep -Fxq "$command" "$tmp_dir/package-cargo.log" \
    || fail "package preflight omitted $command"
done
for mode in package-failure build-failure; do
  if run_package_preflight "$mode" >"$tmp_dir/$mode.out" 2>&1; then
    fail "package preflight accepted $mode"
  fi
done

printf 'publish preflight harness passed\n'
