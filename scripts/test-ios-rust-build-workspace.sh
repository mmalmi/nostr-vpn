#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-rust-workspace.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/other-checkout"
printf '[workspace]\nmembers = []\n' >"$temporary/other-checkout/Cargo.toml"
cat >"$temporary/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
set -euo pipefail
[[ "$(pwd -P)" == "$EXPECTED_ROOT" ]] || {
  echo "iOS Rust build used the caller's checkout" >&2
  exit 1
}
printf '%s\n' "$*" >>"$BUILD_CALLS"
CARGO
cat >"$temporary/bin/xcode-select" <<'XCODE'
#!/usr/bin/env bash
printf '/unused-xcode\n'
XCODE
cat >"$temporary/bin/xcrun" <<'XCRUN'
#!/usr/bin/env bash
printf '/unused-sdk\n'
XCRUN
chmod +x "$temporary/bin/"*
(
  cd "$temporary/other-checkout"
  unset NVPN_FIPS_REPO_PATH
  export EXPECTED_ROOT="$ROOT" BUILD_CALLS="$temporary/build-calls"
  PATH="$temporary/bin:$PATH" "$ROOT/tools/run-ios" rust
)
[[ "$(wc -l <"$temporary/build-calls" | tr -d ' ')" == 2 ]]
grep -Fq -- '--no-default-features --target aarch64-apple-ios-sim' "$temporary/build-calls"
grep -Eq -- '--no-default-features --target aarch64-apple-ios( |$)' "$temporary/build-calls"
echo IOS_RUST_BUILD_WORKSPACE_OK
