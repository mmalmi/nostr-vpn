#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="$ROOT/scripts/prepare-android-release-from-bundle.sh"
ANDROID_RUNNER="$ROOT/tools/run-android"
PHYSICAL="$ROOT/scripts/lib-mobile-android-release-gate.sh"
PUBLISH="$ROOT/scripts/local-release.mjs"

fail() {
  echo "Android AAB-derived release contract failed: $*" >&2
  exit 1
}

require_token() {
  local path="$1" token="$2"
  grep -Fq -- "$token" "$path" || fail "$(basename "$path") lacks: $token"
}

bash -n "$BUILDER" "$ANDROID_RUNNER" "$PHYSICAL"
[[ -x "$BUILDER" ]] || fail "bundle-derived APK builder is not executable"

require_token "$ANDROID_RUNNER" ':app:bundleRelease'
require_token "$ANDROID_RUNNER" 'prepare-android-release-from-bundle.sh'
if sed -n '/release|assembleRelease)/,/;;/p' "$ANDROID_RUNNER" \
  | grep -Fq ':app:assembleRelease'
then
  fail "canonical Release path still assembles an independent APK"
fi

for token in \
  'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29' \
  'build-apks' \
  '--mode=universal' \
  "grep -Fxc 'universal.apk'" \
  'universal-apk-derived-from-exact-aab' \
  'physical-gate-artifact.json' \
  'jarsigner -verify' \
  'apksigner' \
  'acquire_gate_lock' \
  'invalidate_gate_artifacts' \
  'ARTIFACTS_COMMITTED=1'
do
  require_token "$BUILDER" "$token"
done

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-aab-derived-fixture.XXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT
python3 - "$fixture_root" <<'PY'
import pathlib
import sys
import warnings
import zipfile

root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(root / "valid.apks", "w") as archive:
    archive.writestr("universal.apk", b"exact-universal-apk")
    archive.writestr("toc.pb", b"fixture")
with zipfile.ZipFile(root / "nested.apks", "w") as archive:
    archive.writestr("nested/universal.apk", b"wrong-path")
with zipfile.ZipFile(root / "empty.apks", "w") as archive:
    archive.writestr("universal.apk", b"")
with warnings.catch_warnings():
    warnings.simplefilter("ignore", UserWarning)
    with zipfile.ZipFile(root / "duplicate.apks", "w") as archive:
        archive.writestr("universal.apk", b"first")
        archive.writestr("universal.apk", b"second")
PY

# Exercise the exact production extraction function, including the literal
# member-name contract that caught the previous overescaped regular expression.
# shellcheck disable=SC1090
NVPN_ANDROID_BUNDLE_LIBRARY_ONLY=1
source "$BUILDER"
unset NVPN_ANDROID_BUNDLE_LIBRARY_ONLY
extract_single_universal_apk \
  "$fixture_root/valid.apks" "$fixture_root/extracted.apk"
[[ "$(<"$fixture_root/extracted.apk")" == "exact-universal-apk" ]] \
  || fail "production extraction changed the universal APK bytes"
for invalid in nested empty duplicate; do
  if bash -c \
    'NVPN_ANDROID_BUNDLE_LIBRARY_ONLY=1
     source "$1"
     extract_single_universal_apk "$2" "$3"' \
    bash "$BUILDER" "$fixture_root/$invalid.apks" \
    "$fixture_root/$invalid.apk" >/dev/null 2>&1
  then
    fail "production extraction accepted the $invalid APKS fixture"
  fi
done

# A failed new preparation must invalidate both old consumer-visible files.
mkdir -p "$fixture_root/output"
printf 'stale-apk\n' >"$fixture_root/output/app-release.apk"
printf 'stale-receipt\n' >"$fixture_root/output/physical-gate-artifact.json"
bash -c '
  NVPN_ANDROID_BUNDLE_LIBRARY_ONLY=1
  source "$1"
  APK="$2"
  RECEIPT="$3"
  APK_STAGE=""
  RECEIPT_STAGE=""
  TEMP_DIR=""
  ARTIFACTS_COMMITTED=0
  LOCK_DIR="$4"
  mkdir "$LOCK_DIR"
  printf "%s\n" "$$" >"$LOCK_DIR/owner"
  LOCK_OWNED=1
  cleanup
' bash "$BUILDER" \
  "$fixture_root/output/app-release.apk" \
  "$fixture_root/output/physical-gate-artifact.json" \
  "$fixture_root/output/artifact.lock"
[[ ! -e "$fixture_root/output/app-release.apk" \
  && ! -e "$fixture_root/output/physical-gate-artifact.json" ]] \
  || fail "failed preparation retained stale APK/receipt outputs"

lock="$fixture_root/concurrent.lock"
bash -c '
  NVPN_ANDROID_BUNDLE_LIBRARY_ONLY=1
  source "$1"
  LOCK_DIR="$2"
  acquire_gate_lock
  exec sleep 10
' bash "$BUILDER" "$lock" &
lock_owner=$!
for _ in $(seq 1 100); do
  [[ -s "$lock/owner" ]] && break
  sleep 0.01
done
[[ -s "$lock/owner" ]] || fail "lock fixture did not acquire the production lock"
if bash -c '
  NVPN_ANDROID_BUNDLE_LIBRARY_ONLY=1
  source "$1"
  LOCK_DIR="$2"
  acquire_gate_lock
' bash "$BUILDER" "$lock" >/dev/null 2>&1
then
  fail "concurrent Android artifact builder acquired an owned lock"
fi
kill "$lock_owner"
wait "$lock_owner" >/dev/null 2>&1 || true
bash -c '
  NVPN_ANDROID_BUNDLE_LIBRARY_ONLY=1
  source "$1"
  LOCK_DIR="$2"
  acquire_gate_lock
' bash "$BUILDER" "$lock"

python3 - "$BUILDER" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
apk_move = source.index('mv -f "$APK_STAGE" "$APK"')
receipt_move = source.index('mv -f "$RECEIPT_STAGE" "$RECEIPT"')
commit = source.index("ARTIFACTS_COMMITTED=1")
if not apk_move < receipt_move < commit:
    raise SystemExit(
        "receipt is not the final commit marker for Android artifact promotion"
    )
PY

for token in \
  '"aabSha256": actual_aab_sha' \
  '"apkDerivedFromAab": True' \
  '"bundleReceiptSha256":' \
  'Android APK is not derived from the exact Play AAB'
do
  require_token "$PHYSICAL" "$token"
done

for token in \
  "validateAndroidBundleRelationship(bundleReceipt" \
  "sha256FileSync(aabDest) !== gate.aabSha256" \
  "physical-gate-sealed bundletool-derived APK"
do
  require_token "$PUBLISH" "$token"
done

python3 "$ROOT/scripts/test-android-unbuilt-artifact.py"

echo "ANDROID_AAB_DERIVED_RELEASE_CONTRACT_OK"
