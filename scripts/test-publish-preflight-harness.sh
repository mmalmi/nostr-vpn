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
# Exercise Cargo itself: the old local check accepted an API provided only by
# a workspace patch, while the distributable package used registry sources.
awk '
  /^verify_cargo_packages\(\) \{/ { emit = 1 }
  /^publish_tier\(\) \{/ { exit }
  emit { print }
' "$PUBLISHER" >"$tmp_dir/package-function.sh"
[[ -s "$tmp_dir/package-function.sh" ]] || fail "could not extract package preflight"
fixture="$tmp_dir/workspace"
mkdir -p "$fixture/core/src" "$fixture/cli/src" "$fixture/itoa/src"
cat >"$fixture/Cargo.toml" <<'EOF'
[workspace]
members = ["core", "cli"]
exclude = ["itoa"]
resolver = "2"
[patch.crates-io]
itoa = { path = "itoa" }
EOF
cat >"$fixture/core/Cargo.toml" <<'EOF'
[package]
name = "nvpn-package-preflight-core-fixture"
version = "0.1.0"
edition = "2021"
description = "Disposable Cargo preflight regression fixture"
license = "MIT"
[dependencies]
itoa = "=1.0.18"
EOF
cat >"$fixture/cli/Cargo.toml" <<'EOF'
[package]
name = "nvpn-package-preflight-cli-fixture"
version = "0.1.0"
edition = "2021"
description = "Disposable Cargo preflight regression fixture"
license = "MIT"
[dependencies]
nvpn-package-preflight-core-fixture = { path = "../core", version = "=0.1.0" }
EOF
cat >"$fixture/itoa/Cargo.toml" <<'EOF'
[package]
name = "itoa"
version = "1.0.18"
edition = "2021"
EOF
printf 'pub fn nvpn_local_only() -> String { "42".into() }\n' >"$fixture/itoa/src/lib.rs"
printf 'pub fn value() -> String { itoa::nvpn_local_only() }\n' >"$fixture/core/src/lib.rs"
printf 'fn main() { println!("{}", nvpn_package_preflight_core_fixture::value()); }\n' >"$fixture/cli/src/main.rs"
(
  cd "$fixture"
  git init -q
  cargo generate-lockfile --offline
  git add .
  git -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm fixture
  cargo check --locked --offline -p nvpn-package-preflight-cli-fixture
) >"$tmp_dir/local-check.log" 2>&1 || { cat "$tmp_dir/local-check.log"; fail "local fixture must build"; }
run_real_package_preflight() {
  (
    cd "$fixture"
    source "$tmp_dir/package-function.sh"
    ALL_CRATES=(nvpn-package-preflight-core-fixture nvpn-package-preflight-cli-fixture)
    # Allow Cargo to fetch the tiny pinned registry fixture on a fresh CI host.
    CARGO_NET_OFFLINE=false verify_cargo_packages
  )
}
if run_real_package_preflight >"$tmp_dir/rejected.log" 2>&1; then
  fail "package preflight accepted a local-only dependency API"
fi
grep -Fq 'cannot find function `nvpn_local_only`' "$tmp_dir/rejected.log" \
  || { cat "$tmp_dir/rejected.log"; fail "fixture failed for an unexpected reason"; }
# A compatible package must build even though neither workspace crate exists
# in the public registry yet. This is the path needed before any publication.
printf 'pub fn value() -> String { itoa::Buffer::new().format(42).to_owned() }\n' >"$fixture/core/src/lib.rs"
(
  cd "$fixture"
  git add core/src/lib.rs
  git -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm compatible
)
run_real_package_preflight >"$tmp_dir/accepted.log" 2>&1 \
  || { cat "$tmp_dir/accepted.log"; fail "compatible unpublished packages did not build"; }
printf 'publish preflight harness passed: local-only API rejected; unpublished package graph verified\n'
