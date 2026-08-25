#!/usr/bin/env bash
# Self-test lockfile hygiene for direct mobile platform build entry points.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail() {
  printf 'mobile platform tools self-test failed: %s\n' "$*" >&2
  exit 1
}

make_fips_fixture() {
  local dir="$1"
  local crate package
  for crate in fips-core fips-endpoint fips-identity; do
    package="nvpn-$crate"
    mkdir -p "$dir/crates/$crate"
    printf '[package]\nname = "%s"\nversion = "0.0.0"\n' "$package" \
      >"$dir/crates/$crate/Cargo.toml"
  done
  git -C "$dir" init -q
  git -C "$dir" add .
  git -C "$dir" \
    -c user.name=Harness -c user.email=harness.invalid commit -qm fixture
}

assert_failed_run_restores_lock() {
  local label="$1"
  shift
  local lock_snapshot manifest_snapshot out rc
  lock_snapshot="$(mktemp)"
  manifest_snapshot="$(mktemp)"
  cp -p "$ROOT/Cargo.lock" "$lock_snapshot"
  cp -p "$ROOT/Cargo.toml" "$manifest_snapshot"

  set +e
  out="$("$@" 2>&1)"
  rc=$?
  set -e

  if (( rc == 0 )); then
    rm -f "$lock_snapshot" "$manifest_snapshot"
    printf '%s\n' "$out" >&2
    fail "$label unexpectedly passed"
  fi
  if ! cmp -s "$lock_snapshot" "$ROOT/Cargo.lock"; then
    cp -p "$lock_snapshot" "$ROOT/Cargo.lock"
    rm -f "$lock_snapshot" "$manifest_snapshot"
    printf '%s\n' "$out" >&2
    fail "$label left Cargo.lock modified"
  fi
  if ! cmp -s "$manifest_snapshot" "$ROOT/Cargo.toml"; then
    cp -p "$manifest_snapshot" "$ROOT/Cargo.toml"
    rm -f "$lock_snapshot" "$manifest_snapshot"
    printf '%s\n' "$out" >&2
    fail "$label left Cargo.toml modified"
  fi
  rm -f "$lock_snapshot" "$manifest_snapshot"
  grep -Fq 'restored Cargo.lock after local-FIPS cargo run' <<<"$out" \
    || fail "$label did not report Cargo.lock restore"
  if grep -Fq 'restored Cargo.toml after local-FIPS cargo run' <<<"$out"; then
    fail "$label still mutates the shared Cargo.toml"
  fi
}

test_run_ios_restores_lock_after_failed_local_fips_cargo() {
  local dir stubbin fips
  dir="$(mktemp -d)"
  stubbin="$dir/bin"
  fips="$dir/fips"
  mkdir -p "$stubbin" "$dir/xcode/Toolchains/XcodeDefault.xctoolchain/usr/bin" "$dir/sdk"
  make_fips_fixture "$fips"

  cat >"$stubbin/xcode-select" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "-p" ]] || exit 2
printf '%s\n' "$NVPN_TEST_XCODE_ROOT"
EOF
  cat >"$stubbin/xcrun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--sdk" && "${3:-}" == "--show-sdk-path" ]]; then
  printf '%s/%s\n' "$NVPN_TEST_SDK_ROOT" "$2"
  exit 0
fi
exit 2
EOF
cat >"$stubbin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" \
  | grep -Fq "patch.crates-io.nvpn-fips-core.path=\"$NVPN_TEST_FIPS_REPO_PATH/crates/fips-core\""
printf '\n# mutated by fake iOS cargo\n' >> "$NVPN_TEST_CARGO_LOCK"
exit 42
EOF
  chmod +x "$stubbin/xcode-select" "$stubbin/xcrun" "$stubbin/cargo"

  assert_failed_run_restores_lock \
    "run-ios local-FIPS cargo failure" \
    env \
      PATH="$stubbin:$PATH" \
      NVPN_TEST_XCODE_ROOT="$dir/xcode" \
      NVPN_TEST_SDK_ROOT="$dir/sdk" \
      NVPN_TEST_CARGO_LOCK="$ROOT/Cargo.lock" \
      NVPN_TEST_CARGO_MANIFEST="$ROOT/Cargo.toml" \
      NVPN_TEST_FIPS_REPO_PATH="$fips" \
      NVPN_FIPS_REPO_PATH="$fips" \
      "$ROOT/tools/run-ios" rust

  rm -rf "$dir"
}

test_run_android_restores_lock_after_failed_local_fips_gradle() {
  local dir stubbin fips manifest_sha lock_sha fips_path_sha fips_head fips_tree rc
  dir="$(mktemp -d)"
  stubbin="$dir/bin"
  fips="$dir/fips"
  mkdir -p "$stubbin"
  make_fips_fixture "$fips"

  cat >"$stubbin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${NVPN_TEST_PRECONFIGURED:-0}" == "1" ]]; then
  manifest="$(cd "$NVPN_TEST_FIPS_REPO_PATH/crates/fips-core" && pwd -P)/Cargo.toml"
  python3 -c 'import json,sys
m=sys.argv[1]; i=f"path+file://{m}#nvpn-fips-core@0.0.0"
json.dump({"packages":[{"id":i,"manifest_path":m,"name":"nvpn-fips-core",
"source":None,"version":"0.0.0"}],"resolve":{"nodes":[{"id":i}]}},sys.stdout)' \
    "$manifest"
  exit
fi
printf '%s\n' "$*" \
  | grep -Fq "patch.crates-io.nvpn-fips-core.path=\"$NVPN_TEST_FIPS_REPO_PATH/crates/fips-core\""
printf '\n# mutated by fake Android cargo\n' >> "$NVPN_TEST_CARGO_LOCK"
exit 42
EOF
  printf '#!/usr/bin/env bash\nexit 0\n' >"$stubbin/cargo-ndk"
  cat >"$stubbin/gradle" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cargo_executable=""
cargo_ndk_executable=""
for argument in "$@"; do
  case "$argument" in
    -PnvpnCargoExecutable=*)
      cargo_executable="${argument#*=}"
      ;;
    -PnvpnCargoNdkExecutable=*)
      cargo_ndk_executable="${argument#*=}"
      ;;
  esac
done
if [[ "${NVPN_TEST_PRECONFIGURED:-0}" == "1" ]]; then
  printf '%s\n' "$@" >"$NVPN_TEST_GRADLE_ARGS"
  exit 43
fi
[[ -n "$cargo_executable" ]]
[[ "$cargo_executable" == */cargo-wrapper/cargo ]]
[[ -x "$cargo_ndk_executable" ]]
"$cargo_executable" metadata
exit 43
EOF
  chmod +x "$stubbin/cargo" "$stubbin/cargo-ndk" "$stubbin/gradle"

  assert_failed_run_restores_lock \
    "run-android local-FIPS Gradle failure" \
    env \
      PATH="$stubbin:$PATH" \
      HOME="$dir/home" \
      NVPN_TEST_CARGO_LOCK="$ROOT/Cargo.lock" \
      NVPN_TEST_CARGO_MANIFEST="$ROOT/Cargo.toml" \
      NVPN_TEST_FIPS_REPO_PATH="$fips" \
      NVPN_FIPS_REPO_PATH="$fips" \
      "$ROOT/tools/run-android" build

  manifest_sha="$(shasum -a 256 "$ROOT/Cargo.toml" | awk '{print $1}')"
  lock_sha="$(shasum -a 256 "$ROOT/Cargo.lock" | awk '{print $1}')"
  fips_path_sha="$(
    printf '%s' "$(cd "$fips" && pwd -P)" | shasum -a 256 | awk '{print $1}'
  )"
  fips_head="$(git -C "$fips" rev-parse HEAD)"
  fips_tree="$(git -C "$fips" rev-parse 'HEAD^{tree}')"

  rc=0
  env -u NVPN_LOCAL_FIPS_LOCK_DIR \
    PATH="$stubbin:$PATH" \
    HOME="$dir/home" \
    NVPN_FIPS_REPO_PATH="$fips" \
    NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED=1 \
    NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256="$manifest_sha" \
    NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256="$lock_sha" \
    NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256="$fips_path_sha" \
    NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD="$fips_head" \
    NVPN_LOCAL_FIPS_SESSION_FIPS_TREE="$fips_tree" \
    NVPN_ANDROID_FIPS_METADATA_RECEIPT="$dir/fips-linkage.json" \
    NVPN_TEST_FIPS_REPO_PATH="$fips" \
    NVPN_TEST_PRECONFIGURED=1 \
    NVPN_TEST_GRADLE_ARGS="$dir/gradle-args" \
    "$ROOT/tools/run-android" build >/dev/null 2>&1 || rc=$?
  [[ "$rc" -eq 43 && -s "$dir/fips-linkage.json" ]] \
    && grep -Fxq -- "-PnvpnCargoExecutable=$stubbin/cargo" "$dir/gradle-args" \
    && grep -Fxq -- "-PnvpnCargoNdkExecutable=$stubbin/cargo-ndk" "$dir/gradle-args" \
    && ! grep -Fq '/cargo-wrapper/cargo' "$dir/gradle-args" \
    || fail "run-android rejected the preconfigured session Cargo"

  rm -rf "$dir"
}

test_run_ios_restores_lock_after_failed_local_fips_cargo
test_run_android_restores_lock_after_failed_local_fips_gradle

printf 'mobile platform tools self-test passed\n'
