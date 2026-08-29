#!/usr/bin/env bash

# Black-box gate for the exact non-debuggable Android Release APK. This library
# intentionally contains only Release orchestration; UI/query/network
# primitives remain shared with mobile-android-smoke.sh and the external probe
# library.

ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT=""
ANDROID_RELEASE_NATIVE_TUNNEL_START_BASELINE=""

android_release_reuse_verified_artifact() {
  case "${NVPN_ANDROID_RELEASE_REUSE_VERIFIED_ARTIFACT:-0}" in
    1|true|TRUE|True|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

android_release_require_reuse_inputs() {
  [[ "${build:-1}" -eq 0 && "${install:-1}" -eq 0 ]] || {
    echo "Android verified-artifact reuse requires --no-build and --no-install" >&2
    return 1
  }
  ANDROID_RELEASE_REUSE_RECEIPT="${NVPN_MOBILE_ANDROID_RELEASE_RECEIPT:-}"
  ANDROID_RELEASE_REUSE_AAB="${NVPN_ANDROID_RELEASE_REUSE_AAB_PATH:-}"
  ANDROID_RELEASE_REUSE_BUNDLE_RECEIPT="${NVPN_ANDROID_RELEASE_REUSE_BUNDLE_RECEIPT:-}"
  local name path identity
  for name in \
    ANDROID_RELEASE_REUSE_RECEIPT \
    ANDROID_RELEASE_REUSE_AAB \
    ANDROID_RELEASE_REUSE_BUNDLE_RECEIPT
  do
    path="${!name:-}"
    [[ -n "$path" && -f "$path" && ! -L "$path" ]] || {
      echo "Android verified-artifact reuse requires regular file $name" >&2
      return 1
    }
  done
  identity="$(python3 -c '
import json, re, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
h, t = r.get("appGitSha", ""), r.get("appGitTree", "")
if r.get("receiptSchema") != 2 or r.get("artifactType") != "Android Release APK": raise SystemExit(1)
if not re.fullmatch(r"[0-9a-f]{40}", h) or not re.fullmatch(r"[0-9a-f]{40}", t): raise SystemExit(1)
print(h, t)
' "$ANDROID_RELEASE_REUSE_RECEIPT")" || {
    echo "Android verified-artifact reuse requires an exact schema-2 receipt" >&2
    return 1
  }
  read -r EXPECTED_ANDROID_APP_GIT_HEAD EXPECTED_ANDROID_APP_GIT_TREE \
    <<<"$identity"
}

android_release_require_inputs() {
  [[ "$PACKAGE_NAME" == "$CANONICAL_PACKAGE_NAME" ]] || {
    echo "Android Release black-box gate requires canonical package $CANONICAL_PACKAGE_NAME" >&2
    return 1
  }
  if android_release_reuse_verified_artifact; then
    android_release_require_reuse_inputs || return 1
  else
    EXPECTED_ANDROID_APP_GIT_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
    EXPECTED_ANDROID_APP_GIT_TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
    assert_release_checkout_state \
      "$ROOT" "$EXPECTED_ANDROID_APP_GIT_HEAD" \
      "$EXPECTED_ANDROID_APP_GIT_TREE" "Android Release black-box gate" \
      || return 1
    pin_exact_release_build_git_sha \
      "$ROOT" "$EXPECTED_ANDROID_APP_GIT_HEAD" "Android Release" \
      || return 1
  fi
  local name
  for name in \
    ANDROID_KEYSTORE_PATH \
    ANDROID_KEYSTORE_PASSWORD \
    ANDROID_KEY_ALIAS \
    ANDROID_KEY_PASSWORD \
    NVPN_FIPS_REPO_PATH \
    NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256 \
    NVPN_EXPECTED_FIPS_GIT_SHA
  do
    [[ -n "${!name:-}" ]] || {
      echo "Android Release black-box gate requires $name" >&2
      return 1
    }
  done
  [[ -f "$ANDROID_KEYSTORE_PATH" ]] || {
    echo "Android Release keystore does not exist" >&2
    return 1
  }
  command -v keytool >/dev/null 2>&1 || {
    echo "Android Release black-box gate requires keytool for signer verification" >&2
    return 1
  }
  local signer_der configured_signer
  signer_der="$(mktemp "${TMPDIR:-/tmp}/nvpn-android-signer.XXXXXX")"
  if ! env ANDROID_KEYSTORE_PASSWORD="$ANDROID_KEYSTORE_PASSWORD" \
    keytool -exportcert \
      -keystore "$ANDROID_KEYSTORE_PATH" \
      -storepass:env ANDROID_KEYSTORE_PASSWORD \
      -alias "$ANDROID_KEY_ALIAS" >"$signer_der" 2>/dev/null
  then
    rm -f "$signer_der"
    echo "Android Release gate could not export the configured company signer" >&2
    return 1
  fi
  EXPECTED_ANDROID_SIGNER_CERT_SHA256="$(
    shasum -a 256 "$signer_der" | awk '{print tolower($1)}'
  )"
  rm -f "$signer_der"
  configured_signer="${NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256:-}"
  configured_signer="$(
    printf '%s' "$configured_signer" \
      | tr -d ':[:space:]' \
      | tr '[:upper:]' '[:lower:]'
  )"
  [[ "$configured_signer" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Android Release gate requires an exact signer certificate SHA-256 pin" >&2
    return 1
  }
  if [[ "$configured_signer" != "$EXPECTED_ANDROID_SIGNER_CERT_SHA256" ]]
  then
    echo "Configured Android signer digest does not match the company keystore" >&2
    return 1
  fi
  [[ -d "$NVPN_FIPS_REPO_PATH/.git" || -f "$NVPN_FIPS_REPO_PATH/.git" ]] || {
    echo "Android Release black-box gate requires an exact local FIPS checkout" >&2
    return 1
  }
  local fips_head fips_tree fips_dirty fips_version
  fips_head="$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse HEAD)"
  fips_tree="$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse 'HEAD^{tree}')"
  fips_dirty="$(git -C "$NVPN_FIPS_REPO_PATH" status --porcelain)"
  [[ -z "$fips_dirty" ]] || {
    echo "Android Release black-box gate refuses a dirty FIPS checkout" >&2
    return 1
  }
  fips_version="$(
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
    ' "$NVPN_FIPS_REPO_PATH/crates/fips-core/Cargo.toml"
  )"
  [[ "$fips_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
    echo "Android Release gate could not derive the exact FIPS package version" >&2
    return 1
  }
  [[ "$NVPN_EXPECTED_FIPS_GIT_SHA" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Android Release gate requires an exact FIPS Git SHA pin" >&2
    return 1
  }
  if [[ "$fips_head" != "$NVPN_EXPECTED_FIPS_GIT_SHA" ]]; then
    echo "Android Release black-box FIPS mismatch: expected $NVPN_EXPECTED_FIPS_GIT_SHA, got $fips_head" >&2
    return 1
  fi
  EXPECTED_FIPS_GIT_SHA="$NVPN_EXPECTED_FIPS_GIT_SHA"
  EXPECTED_FIPS_GIT_TREE="$fips_tree"
  EXPECTED_FIPS_VERSION="$fips_version"
  export NVPN_EXPECTED_FIPS_VERSION="$fips_version"
  [[ -n "$RELEASE_WIREGUARD_CONFIG_FILE" || -n "$RELEASE_WIREGUARD_CONFIG" ]] || {
    echo "Android Release black-box gate requires WireGuard config for real UI entry" >&2
    return 1
  }
  [[ -n "$EXIT_PROBE_HOST" && -n "$CAPTURED_PROBE_URL" \
    && -n "$CAPTURED_PROBE_TOKEN" && -n "$EXIT_SOURCE_PROBE_URL" \
    && -n "$EXPECTED_EXIT_SOURCE_IP" ]] || {
    echo "Android Release black-box gate requires external DNS/HTTP/HTTPS/exit-source probes" >&2
    return 1
  }
}

android_release_apksigner() {
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  [[ -n "$sdk" ]] || sdk="$(sdk_from_local_properties)"
  find "$sdk/build-tools" -type f -name apksigner 2>/dev/null \
    | sort -V \
    | tail -n 1
}

android_release_validate_reused_artifact() {
  local metadata_receipt
  metadata_receipt="${NVPN_ANDROID_FIPS_METADATA_RECEIPT:-$ROOT/artifacts/mobile-android/fips-linkage.json}"
  [[ -f "$metadata_receipt" && ! -L "$metadata_receipt" ]] || {
    echo "Android verified-artifact reuse lacks its FIPS metadata receipt" >&2
    return 1
  }
  python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" validate-android \
    --receipt "$ANDROID_RELEASE_REUSE_RECEIPT" \
    --apk "$APK_PATH" \
    --aab "$ANDROID_RELEASE_REUSE_AAB" \
    --bundle-receipt "$ANDROID_RELEASE_REUSE_BUNDLE_RECEIPT" \
    --fips-metadata "$metadata_receipt" \
    --app-root "$ROOT" \
    --fips-root "$NVPN_FIPS_REPO_PATH" \
    --app-head "$EXPECTED_ANDROID_APP_GIT_HEAD" \
    --app-tree "$EXPECTED_ANDROID_APP_GIT_TREE" \
    --fips-head "$EXPECTED_FIPS_GIT_SHA" \
    --fips-tree "$EXPECTED_FIPS_GIT_TREE" \
    --fips-version "$EXPECTED_FIPS_VERSION" \
    --package "$CANONICAL_PACKAGE_NAME" \
    --actual-package "$PACKAGE_NAME" \
    --signer-sha "$EXPECTED_ANDROID_SIGNER_CERT_SHA256" \
    || return 1
}

verify_android_release_install() {
  local apksigner remote_path pulled apk_sha installed_sha cert_sha receipt
  local native_lib native_strings target_root metadata_receipt rebuild_marker
  local dep_file metadata_sha metadata_path_sha fips_path_sha
  local bundle_receipt aab_path
  apksigner="$(android_release_apksigner)"
  [[ -x "$apksigner" ]] || {
    echo "Android Release black-box gate could not find apksigner" >&2
    return 1
  }
  "$apksigner" verify "$APK_PATH" >/dev/null || {
    echo "Android Release APK signature verification failed" >&2
    return 1
  }
  remote_path="$(
    "$ADB" -s "$serial" shell pm path "$PACKAGE_NAME" 2>/dev/null \
      | tr -d '\r' \
      | sed -n 's/^package://p' \
      | head -n 1
  )"
  [[ -n "$remote_path" ]] || {
    echo "Android Release install has no canonical package path" >&2
    return 1
  }
  pulled="$(mktemp "${TMPDIR:-/tmp}/nvpn-installed-release.XXXXXX")"
  if ! "$ADB" -s "$serial" pull "$remote_path" "$pulled" >/dev/null 2>&1; then
    rm -f "$pulled"
    echo "Android Release installed APK could not be copied for exact comparison" >&2
    return 1
  fi
  apk_sha="$(shasum -a 256 "$APK_PATH" | awk '{print $1}')"
  installed_sha="$(shasum -a 256 "$pulled" | awk '{print $1}')"
  rm -f "$pulled"
  [[ "$apk_sha" == "$installed_sha" ]] || {
    echo "Android installed APK bytes differ from the tested Release artifact" >&2
    return 1
  }
  if "$ADB" -s "$serial" shell run-as "$PACKAGE_NAME" true >/dev/null 2>&1; then
    echo "Android Release black-box gate refuses a debuggable installed app" >&2
    return 1
  fi
  cert_sha="$(
    "$apksigner" verify --print-certs "$APK_PATH" 2>/dev/null \
      | awk 'index($0, "certificate SHA-256 digest: ") { sub(/^.*certificate SHA-256 digest: /, ""); print; exit }' \
      | head -n 1
  )"
  [[ "$cert_sha" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "Android Release APK has no signer certificate receipt" >&2
    return 1
  }
  local normalized_cert_sha
  normalized_cert_sha="$(
    printf '%s' "$cert_sha" | tr '[:upper:]' '[:lower:]'
  )"
  if [[ "$normalized_cert_sha" != "$EXPECTED_ANDROID_SIGNER_CERT_SHA256" ]]; then
    echo "Android Release APK is not signed by the configured company keystore" >&2
    return 1
  fi
  if android_release_reuse_verified_artifact; then
    android_release_validate_reused_artifact || return 1
    echo "Android exact sealed Release artifact verified without rebuild, install, or receipt rewrite"
    return 0
  fi
  native_lib="$(mktemp "${TMPDIR:-/tmp}/nvpn-android-release-native.XXXXXX")"
  if ! unzip -p "$APK_PATH" \
      lib/arm64-v8a/libnostr_vpn_app_core.so >"$native_lib"
  then
    rm -f "$native_lib"
    echo "Android Release APK has no production native library" >&2
    return 1
  fi
  native_strings="$(mktemp "${TMPDIR:-/tmp}/nvpn-android-release-strings.XXXXXX")"
  strings "$native_lib" >"$native_strings"
  if ! grep -Fq "${NVPN_FIPS_REPO_PATH%/}/crates/fips-core/src/" "$native_strings" \
    || ! grep -Fq 'fips_core::node' "$native_strings" \
    || ! grep -Fq 'fips_core::transport' "$native_strings"
  then
    rm -f "$native_lib" "$native_strings"
    echo "Android Release native library lacks exact-checkout FIPS production code" >&2
    return 1
  fi
  rm -f "$native_strings"
  target_root="${CARGO_TARGET_DIR:-$ROOT/target}"
  [[ "$target_root" = /* ]] || target_root="$ROOT/$target_root"
  dep_file="$(
    python3 - \
      "$target_root/aarch64-linux-android/release" \
      "${NVPN_FIPS_REPO_PATH%/}/crates/fips-core" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
matches = []
for path in root.rglob("fips_core-*.d"):
    try:
        if expected in path.read_text(encoding="utf-8", errors="ignore"):
            matches.append(path)
    except OSError:
        pass
if matches:
    print(max(matches, key=lambda path: path.stat().st_mtime))
PY
  )"
  if [[ -z "$dep_file" ]]; then
    rm -f "$native_lib"
    echo "Android Release dependencies do not prove the exact local FIPS checkout" >&2
    return 1
  fi
  metadata_receipt="${NVPN_ANDROID_FIPS_METADATA_RECEIPT:-$ROOT/artifacts/mobile-android/fips-linkage.json}"
  rebuild_marker="${NVPN_ANDROID_FIPS_REBUILD_MARKER:-$ROOT/artifacts/mobile-android/fips-rebuild-aarch64-linux-android.marker}"
  if ! python3 - \
    "$metadata_receipt" "$rebuild_marker" "$dep_file" "$APK_PATH" \
    "$NVPN_FIPS_REPO_PATH" "$EXPECTED_FIPS_GIT_SHA" \
    "$EXPECTED_FIPS_GIT_TREE" "$EXPECTED_FIPS_VERSION" <<'PY'
import json
import hashlib
import os
import sys

(
    receipt_path,
    marker_path,
    dep_path,
    artifact_path,
    checkout,
    head,
    tree,
    version,
) = sys.argv[1:]
receipt = json.load(open(receipt_path, encoding="utf-8"))
expected_checkout_hash = hashlib.sha256(
    os.path.realpath(checkout).encode()
).hexdigest()
if receipt.get("checkoutPathSha256") != expected_checkout_hash:
    raise SystemExit("Android Cargo metadata receipt has the wrong FIPS path")
if receipt.get("checkoutHead") != head or receipt.get("checkoutTree") != tree:
    raise SystemExit("Android Cargo metadata receipt has the wrong FIPS tree")
if receipt.get("fipsCoreVersion") != version:
    raise SystemExit("Android Cargo metadata receipt has the wrong FIPS version")
marker_mtime = os.path.getmtime(marker_path)
if os.path.getmtime(dep_path) < marker_mtime:
    raise SystemExit("Android fips-core dep-info predates its forced rebuild")
if os.path.getmtime(artifact_path) < marker_mtime:
    raise SystemExit("Android Release APK predates its forced FIPS rebuild")
PY
  then
    rm -f "$native_lib"
    echo "Android Release FIPS metadata/rebuild receipt failed" >&2
    return 1
  fi
  if [[ "$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse HEAD)" \
      != "$EXPECTED_FIPS_GIT_SHA" \
    || "$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse 'HEAD^{tree}')" \
      != "$EXPECTED_FIPS_GIT_TREE" \
    || -n "$(git -C "$NVPN_FIPS_REPO_PATH" status --porcelain --untracked-files=all)" ]]
  then
    rm -f "$native_lib"
    echo "Android Release app/FIPS source changed during the artifact build" >&2
    return 1
  fi
  if ! assert_release_checkout_state \
    "$ROOT" "$EXPECTED_ANDROID_APP_GIT_HEAD" \
    "$EXPECTED_ANDROID_APP_GIT_TREE" "Android Release artifact build"
  then
    rm -f "$native_lib"
    return 1
  fi
  metadata_sha="$(shasum -a 256 "$metadata_receipt" | awk '{print $1}')"
  metadata_path_sha="$(
    python3 -c \
      'import hashlib,os,sys; print(hashlib.sha256(os.path.realpath(sys.argv[1]).encode()).hexdigest())' \
      "$metadata_receipt"
  )"
  fips_path_sha="$(
    python3 -c \
      'import hashlib,os,sys; print(hashlib.sha256(os.path.realpath(sys.argv[1]).encode()).hexdigest())' \
      "$NVPN_FIPS_REPO_PATH"
  )"
  bundle_receipt="$ROOT/android/app/build/outputs/bundle/release/physical-gate-artifact.json"
  aab_path="$ROOT/android/app/build/outputs/bundle/release/app-release.aab"
  [[ -f "$bundle_receipt" && ! -L "$bundle_receipt" \
    && -f "$aab_path" && ! -L "$aab_path" ]] || {
    rm -f "$native_lib"
    echo "Android Release lacks the exact AAB-derived APK receipt" >&2
    return 1
  }
  rm -f "$native_lib"
  receipt="${NVPN_MOBILE_ANDROID_RELEASE_RECEIPT:-$RUNTIME_STATE_RESULT_DIR/mobile-android-release-artifact.json}"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR" "$(dirname "$receipt")"
  if ! python3 - "$receipt" "$apk_sha" "$EXPECTED_ANDROID_APP_GIT_HEAD" \
    "$EXPECTED_ANDROID_APP_GIT_TREE" \
    "$EXPECTED_FIPS_GIT_SHA" "$PACKAGE_NAME" "$APK_PATH" \
    "$EXPECTED_FIPS_GIT_TREE" \
    "$EXPECTED_FIPS_VERSION" "$metadata_sha" \
    "$metadata_path_sha" "$fips_path_sha" \
    "$EXPECTED_ANDROID_SIGNER_CERT_SHA256" \
    "$bundle_receipt" "$aab_path" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

(
    path,
    apk_sha,
    app_sha,
    app_tree,
    fips_sha,
    package,
    apk_path,
    fips_tree,
    fips_version,
    metadata_sha,
    metadata_path_sha,
    fips_path_sha,
    signer_sha,
    bundle_receipt_path,
    aab_path,
) = sys.argv[1:]
bundle_receipt_file = pathlib.Path(bundle_receipt_path)
aab_file = pathlib.Path(aab_path)
bundle = json.loads(bundle_receipt_file.read_text(encoding="utf-8"))
actual_aab_sha = hashlib.sha256(aab_file.read_bytes()).hexdigest()
actual_aab_path_sha = hashlib.sha256(
    os.path.realpath(aab_path).encode()
).hexdigest()
actual_apk_path_sha = hashlib.sha256(
    os.path.realpath(apk_path).encode()
).hexdigest()
if (
    bundle.get("schema") != 1
    or bundle.get("relationship")
    != "universal-apk-derived-from-exact-aab"
    or bundle.get("appGitSha") != app_sha
    or bundle.get("appGitTree") != app_tree
    or bundle.get("aabSha256") != actual_aab_sha
    or bundle.get("aabPathSha256") != actual_aab_path_sha
    or bundle.get("apkSha256") != apk_sha
    or bundle.get("apkPathSha256") != actual_apk_path_sha
    or bundle.get("bundletoolVersion") != "1.18.3"
    or bundle.get("bundletoolSha256")
    != "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
):
    raise SystemExit("Android APK is not derived from the exact Play AAB")
with open(path, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "receiptSchema": 2,
            "artifactType": "Android Release APK",
            "apkPathSha256": hashlib.sha256(
                os.path.realpath(apk_path).encode()
            ).hexdigest(),
            "apkSha256": apk_sha,
            "installedApkSha256": apk_sha,
            "aabSha256": actual_aab_sha,
            "apkDerivedFromAab": True,
            "bundleReceiptSha256": hashlib.sha256(
                bundle_receipt_file.read_bytes()
            ).hexdigest(),
            "bundletoolVersion": bundle["bundletoolVersion"],
            "bundletoolSha256": bundle["bundletoolSha256"],
            "companySigningVerified": True,
            "signerCertificateSha256": signer_sha,
            "appGitSha": app_sha,
            "appGitTree": app_tree,
            "fipsGitSha": fips_sha,
            "fipsGitTree": fips_tree,
            "fipsCoreVersion": fips_version,
            "fipsCheckoutPathSha256": fips_path_sha,
            "fipsCargoMetadataReceiptPathSha256": metadata_path_sha,
            "fipsCargoMetadataReceiptSha256": metadata_sha,
            "fipsDependenciesForcedRebuilt": True,
            "package": package,
            "replacementInstall": True,
            "debuggable": False,
        },
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
PY
  then
    rm -f "$receipt"
    echo "Android Release artifact receipt generation failed" >&2
    return 1
  fi
  echo "Android exact company-signed Release replacement passed: $receipt"
}

write_android_release_foreground_idle_receipt() {
  local raw_receipt artifact_receipt output
  raw_receipt="$(android_idle_cpu_path)"
  artifact_receipt="${NVPN_MOBILE_ANDROID_RELEASE_RECEIPT:-$RUNTIME_STATE_RESULT_DIR/mobile-android-release-artifact.json}"
  output="${NVPN_ANDROID_FOREGROUND_IDLE_RECEIPT:-$(dirname "$raw_receipt")/receipt.json}"
  node "$ROOT/scripts/android-release-foreground-idle-receipt.mjs" create \
    --artifact-receipt "$artifact_receipt" \
    --raw-receipt "$raw_receipt" \
    --output "$output" \
    --verified-live-context
}

android_release_ensure_network_ui() {
  start_main_activity
  sleep 0.5
  if android_ui_query description "Internet tab" center >/dev/null 2>&1; then
    return 0
  fi
  truthy "$create_network" || {
    echo "Android Release black-box gate needs an existing network or --create-network" >&2
    return 1
  }
  wait_for_android_ui resource network-setup-create || {
    echo "Android shipped Create Network control was unavailable" >&2
    return 1
  }
  tap_android_ui resource network-setup-create || return 1
  replace_android_ui_text network-create-name "$DEBUG_NETWORK_NAME" || return 1
  android_ui_scroll_to resource network-create-submit || return 1
  tap_android_ui resource network-create-submit || return 1
  wait_for_android_ui description "Internet tab" || {
    echo "Android network created through shipped UI did not reach the app shell" >&2
    return 1
  }
  echo "Android Release network created through shipped UI"
}

android_release_open_internet_settings() {
  android_open_internet_settings_ui "Release WireGuard configuration"
}

configure_android_release_wireguard_ui() {
  local config
  config="$(wireguard_config)"
  [[ -n "${config//[[:space:]]/}" ]] || {
    echo "Android Release WireGuard config is empty" >&2
    return 1
  }
  android_release_open_internet_settings || return 1
  android_ui_reset_scroll
  tap_android_ui resource internet-source-picker || {
    echo "Android Release could not open the Internet source picker" >&2
    return 1
  }
  wait_for_android_ui description "Internet source WireGuard VPN" || {
    echo "Android Release Internet source picker did not show WireGuard VPN" >&2
    return 1
  }
  tap_android_ui description "Internet source WireGuard VPN" || {
    echo "Android Release could not select WireGuard VPN as the Internet source" >&2
    return 1
  }
  wait_for_android_ui resource wireguard-config || {
    echo "Android Release WireGuard config field did not appear after source selection" >&2
    android_capture_internet_navigation_failure \
      "Release WireGuard config readiness"
    return 1
  }
  replace_android_ui_multiline_text wireguard-config "$config" || {
    echo "Android Release could not enter the WireGuard config through shipped UI" >&2
    return 1
  }
  android_ui_scroll_to resource wireguard-save || {
    echo "Android Release could not find the WireGuard Save control" >&2
    return 1
  }
  tap_android_ui resource wireguard-save || {
    echo "Android Release could not tap the WireGuard Save control" >&2
    return 1
  }
  sleep 1
  # Multiline entry leaves this card scrolled below its Enabled switch.
  # Return to the top before inspecting the switch; the generic scroll helper
  # only searches downward and would otherwise spend its full timeout moving
  # away from the control.
  android_ui_reset_scroll
  android_ui_scroll_to resource wireguard-enabled || {
    echo "Android Release could not return to the WireGuard Enabled control" >&2
    return 1
  }
  local checked
  checked="$(android_ui_query resource wireguard-enabled checked)" || {
    echo "Android Release could not read the WireGuard Enabled control" >&2
    return 1
  }
  case "$checked" in
    false)
      tap_android_ui resource wireguard-enabled || {
        echo "Android Release could not enable the saved WireGuard config" >&2
        return 1
      }
      ;;
    true) ;;
    *)
      echo "Android Release WireGuard toggle state was unavailable" >&2
      return 1
      ;;
  esac
  local deadline=$((SECONDS + ANDROID_UI_WAIT_SECS))
  while ((SECONDS < deadline)); do
    if [[ "$(android_ui_query resource wireguard-enabled checked 2>/dev/null || true)" == "true" ]]; then
      echo "Android Release WireGuard config saved and enabled through shipped UI"
      return 0
    fi
    sleep 0.25
  done
  echo "Android Release WireGuard toggle did not stay enabled" >&2
  return 1
}

android_release_vpn_toggle_checked() {
  start_main_activity
  local deadline=$((SECONDS + ANDROID_UI_WAIT_SECS))
  while ((SECONDS < deadline)); do
    if android_release_vpn_toggle_checked_now; then
      return
    fi
    sleep 0.25
  done
  return 1
}

android_release_vpn_toggle_checked_now() {
  android_ui_vpn_toggle_checked
}

android_release_vpn_off_and_inactive() {
  vpn_inactive || return 1
  [[ "$(android_release_vpn_toggle_checked_now 2>/dev/null || true)" == "false" ]]
}

android_release_wait_stable_quiescence() {
  local label="${1:-cleanup}" expected_count="${2:-}"
  local stable_ms=1000 start_ms deadline_ms now_ms
  local checked="" count="" stable_count="" stable_since_ms=""
  if [[ -n "$expected_count" && ! "$expected_count" =~ ^[0-9]+$ ]]; then
    echo "Android Release $label has no valid expected native-tunnel start count" >&2
    return 1
  fi

  start_main_activity || return 1
  start_ms="$(epoch_ms)"
  deadline_ms=$((start_ms + VPN_STOP_WAIT_SECS * 1000))
  while true; do
    checked="$(android_release_vpn_toggle_checked_now 2>/dev/null || true)"
    count="$(android_vpn_native_start_count 2>/dev/null || true)"
    now_ms="$(epoch_ms)"
    if vpn_inactive \
      && [[ "$checked" == "false" && "$count" =~ ^[0-9]+$ ]] \
      && { [[ -z "$expected_count" ]] || [[ "$count" == "$expected_count" ]]; }
    then
      if [[ "$stable_count" != "$count" || -z "$stable_since_ms" ]]; then
        stable_count="$count"
        stable_since_ms="$now_ms"
      elif (( now_ms - stable_since_ms >= stable_ms )); then
        echo "Android Release $label stable quiescence passed: VPN inactive, shipped toggle Off, native starts=$count for >=${stable_ms}ms"
        return 0
      fi
    else
      stable_count=""
      stable_since_ms=""
    fi
    if (( now_ms >= deadline_ms )); then
      echo "Android Release $label did not reach stable quiescence: vpnInactive=$(vpn_inactive && printf true || printf false) toggle=${checked:-unavailable} nativeStarts=${count:-unavailable} expected=${expected_count:-stable}" >&2
      return 1
    fi
    sleep 0.1
  done
}

android_release_connect_ui() {
  local checked
  checked="$(android_release_vpn_toggle_checked)" || return 1
  [[ "$checked" == "false" ]] || {
    echo "Android Release VPN toggle was already on before the UI connect" >&2
    return 1
  }
  tap_android_ui description "Turn VPN on" || return 1
  maybe_accept_vpn_dialog
  wait_until "$VPN_START_WAIT_SECS" vpn_active || {
    echo "Android Release VPN did not connect through the shipped toggle" >&2
    return 1
  }
  [[ "$(android_release_vpn_toggle_checked)" == "true" ]] || {
    echo "Android Release shipped VPN toggle did not report On" >&2
    return 1
  }
  echo "Android Release VPN connected through shipped UI"
}

android_release_disconnect_ui() {
  local checked
  checked="$(android_release_vpn_toggle_checked)" || {
    echo "Android Release shipped VPN toggle was unavailable during disconnect" >&2
    return 1
  }
  if [[ "$checked" == "true" ]]; then
    tap_android_ui description "Turn VPN off" || return 1
  fi
  if ! wait_until "$VPN_STOP_WAIT_SECS" android_release_vpn_off_and_inactive; then
    start_main_activity || return 1
    checked="$(android_release_vpn_toggle_checked)" || return 1
    if [[ "$checked" == "true" ]]; then
      echo "Android Release VPN-off gesture produced no UI state change; retrying once"
      tap_android_ui description "Turn VPN off" || return 1
    fi
    wait_until "$VPN_STOP_WAIT_SECS" android_release_vpn_off_and_inactive || {
      echo "Android Release VPN did not reach OS-inactive / shipped-toggle-Off state" >&2
      return 1
    }
  fi
  echo "Android Release VPN disconnected through shipped UI"
}

android_release_emergency_cleanup() {
  if android_release_disconnect_ui \
    && android_release_wait_stable_quiescence emergency-cleanup
  then
    return 0
  fi
  echo "Android Release shipped-UI cleanup was incomplete; force-stopping only as an emergency fallback" >&2
  "$ADB" -s "$serial" shell am force-stop "$PACKAGE_NAME" \
    >/dev/null 2>&1 || true
  android_release_disconnect_ui \
    && android_release_wait_stable_quiescence \
      emergency-cleanup-after-force-stop
}

run_android_release_direct_https_probe() {
  local label="$1" result_path
  android_build_captured_network_probe || return 1
  result_path="$(android_network_probe_path "$label-direct-https")"
  if ! "$ADB" -s "$serial" shell \
      env "CLASSPATH=$ANDROID_CAPTURED_PROBE_REMOTE_JAR" \
      app_process /system/bin MobileAndroidCapturedNetworkProbe \
      "$DIRECT_PROBE_URL" >"$result_path" 2>&1
  then
    echo "Android Release $label external HTTPS probe failed: $result_path" >&2
    return 1
  fi
  grep -Eq '^directHttpsStatus=[23][0-9][0-9]$' "$result_path" || {
    echo "Android Release $label external HTTPS receipt is invalid: $result_path" >&2
    return 1
  }
}

run_android_release_direct_network_probe() {
  local label="$1" connected="${2:-0}" result_path route_status dns_servers=""
  result_path="$(android_network_probe_path "$label")"
  mkdir -p "$RUNTIME_STATE_RESULT_DIR"
  if truthy "$connected"; then
    vpn_active || {
      echo "Android Release $label expected the OS VPN to remain connected" >&2
      return 1
    }
    route_status=0
    android_vpn_has_default_route || route_status=$?
    case "$route_status" in
      0)
        echo "Android Release $label VPN still owned a default route" >&2
        return 1
        ;;
      1) ;;
      *)
        echo "Android Release $label could not inspect VPN routes" >&2
        return 1
        ;;
    esac
    dns_servers="$(android_vpn_dns_servers 2>/dev/null)" || {
      echo "Android Release $label could not inspect the connected VPN DNS policy" >&2
      return 1
    }
    [[ -z "$dns_servers" ]] || {
      echo "Android Release $label VPN still owned DNS" >&2
      return 1
    }
  else
    vpn_inactive || {
      echo "Android Release $label expected no VPN service/network" >&2
      return 1
    }
  fi
  {
    printf 'label=%s\n' "$label"
    "$ADB" -s "$serial" shell ping -c 3 -W 3 "$DIRECT_PROBE_HOST"
  } >"$result_path" 2>&1 || {
    echo "Android Release $label external DNS/Internet probe failed: $result_path" >&2
    return 1
  }
  run_android_release_direct_https_probe "$label" || return 1
  echo "Android Release $label external DNS/HTTPS passed: $result_path"
}

run_android_release_exit_network_probe() {
  local label="${1:-wireguard-exit}" dns_servers result_path resolved_ip
  vpn_active || {
    echo "Android Release $label expected the production VPN service/network" >&2
    return 1
  }
  dns_servers="$(android_vpn_dns_servers)" || {
    echo "Android Release $label could not inspect VPN DNS" >&2
    return 1
  }
  grep -Fxq "$EXPECTED_VPN_DNS" <<<"$dns_servers" || {
    echo "Android Release $label VPN DNS was not the production local stub" >&2
    return 1
  }
  android_vpn_has_default_route || {
    echo "Android Release $label VPN did not own the default route" >&2
    return 1
  }
  result_path="$(android_network_probe_path "$label")"
  android_build_captured_network_probe || return 1
  {
    printf 'vpnDnsServers=%s\n' "$(tr '\n' ',' <<<"$dns_servers" | sed 's/,$//')"
    "$ADB" -s "$serial" shell \
      env "CLASSPATH=$ANDROID_CAPTURED_PROBE_REMOTE_JAR" \
      app_process /system/bin MobileAndroidCapturedNetworkProbe \
      --fresh-dns "$EXIT_PROBE_HOST" "$EXIT_PROBE_EXPECTED_IP" "$label"
  } >"$result_path" 2>&1 || {
    echo "Android Release $label fresh DNS probe failed: $result_path" >&2
    return 1
  }
  resolved_ip="$(sed -n 's/.* expectedAddress=\([^ ]*\) .*/\1/p' "$result_path" | head -n 1)"
  if [[ -n "$EXIT_PROBE_EXPECTED_IP" && "$resolved_ip" != "$EXIT_PROBE_EXPECTED_IP" ]]; then
    echo "Android Release $label resolver returned the wrong address: $result_path" >&2
    return 1
  fi
  if ! "$ADB" -s "$serial" shell \
      env "CLASSPATH=$ANDROID_CAPTURED_PROBE_REMOTE_JAR" \
      app_process /system/bin MobileAndroidCapturedNetworkProbe \
      "$CAPTURED_PROBE_URL" "$CAPTURED_PROBE_TOKEN" "$EXIT_PROBE_URL" \
      "$EXIT_SOURCE_PROBE_URL" "$EXPECTED_EXIT_SOURCE_IP" \
      >>"$result_path" 2>&1
  then
    echo "Android Release $label external HTTP/HTTPS/exit-source probe failed: $result_path" >&2
    return 1
  fi
  grep -Fq "token=$CAPTURED_PROBE_TOKEN" "$result_path" \
    && grep -Fq "exitSourceIp=$EXPECTED_EXIT_SOURCE_IP" "$result_path" \
    && grep -Eq 'capturedHttpStatus=200 capturedHttpsStatus=[23][0-9][0-9]' \
      "$result_path" \
    || {
      echo "Android Release $label external packet receipt is incomplete: $result_path" >&2
      return 1
    }
  echo "Android Release $label real DNS/HTTP/HTTPS/exit-source path passed: $result_path"
}

android_release_capture_native_tunnel_start_baseline() {
  local count
  android_vpn_begin_log_window || {
    echo "Android Release could not begin a bounded native-tunnel log window" >&2
    return 1
  }
  count="$(android_vpn_native_start_count)" || {
    echo "Android Release could not inspect native-tunnel starts" >&2
    return 1
  }
  if [[ ! "$count" =~ ^[0-9]+$ ]]; then
    echo "Android Release native-tunnel start baseline is invalid" >&2
    return 1
  fi
  if [[ "$count" != 0 ]]; then
    echo "Android Release observed an unexpected native-tunnel start while establishing its pre-connect log window" >&2
    return 1
  fi
  ANDROID_RELEASE_NATIVE_TUNNEL_START_BASELINE="$count"
}

android_release_pin_native_tunnel_start_count() {
  local count expected wait_seconds deadline
  if [[ ! "$ANDROID_RELEASE_NATIVE_TUNNEL_START_BASELINE" =~ ^[0-9]+$ ]]; then
    echo "Android Release has no pre-connect native-tunnel start baseline" >&2
    return 1
  fi
  expected=$((ANDROID_RELEASE_NATIVE_TUNNEL_START_BASELINE + 1))
  wait_seconds="${NVPN_ANDROID_NATIVE_START_RECEIPT_WAIT_SECS:-4}"
  [[ "$wait_seconds" =~ ^[1-9][0-9]*$ ]] \
    && (( wait_seconds <= 4 )) || {
    echo "Android Release native-tunnel receipt wait must be 1-4 seconds" >&2
    return 1
  }
  deadline=$((SECONDS + wait_seconds))
  while true; do
    count="$(android_vpn_native_start_count)" || {
      echo "Android Release could not inspect native-tunnel starts" >&2
      return 1
    }
    if [[ ! "$count" =~ ^[0-9]+$ \
      || "$count" -lt "$ANDROID_RELEASE_NATIVE_TUNNEL_START_BASELINE" \
      || "$count" -gt "$expected" ]]
    then
      echo "Android Release UI connect expected exactly one native-tunnel start ($ANDROID_RELEASE_NATIVE_TUNNEL_START_BASELINE->$expected), observed ${count:-invalid}" >&2
      return 1
    fi
    if [[ "$count" -eq "$expected" ]]; then
      ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT="$count"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      echo "Android Release UI connect emitted no native-tunnel start within ${wait_seconds}s" >&2
      return 1
    fi
    sleep 0.1
  done
}

android_release_assert_native_tunnel_unchanged() {
  local label="${1:-network phase}" count
  if [[ ! "$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT" =~ ^[1-9][0-9]*$ ]]; then
    echo "Android Release $label has no pinned native-tunnel start count" >&2
    return 1
  fi
  count="$(android_vpn_native_start_count)" || {
    echo "Android Release $label could not inspect native-tunnel starts" >&2
    return 1
  }
  if [[ "$count" != "$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT" ]]; then
    echo "Android Release $label recreated the native tunnel ($ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT->$count)" >&2
    return 1
  fi
}

android_release_accept_single_native_tunnel_refresh() {
  local label="${1:-network refresh}" expected_pid="${2:-}"
  local before expected count
  [[ "$expected_pid" =~ ^[1-9][0-9]*$ ]] || {
    echo "Android Release $label has no pinned canonical app process" >&2
    return 1
  }
  before="$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT"
  if [[ ! "$before" =~ ^[1-9][0-9]*$ ]]; then
    echo "Android Release $label has no pinned native-tunnel start count" >&2
    return 1
  fi
  expected=$((before + 1))
  count="$(android_vpn_native_start_count)" || {
    echo "Android Release $label could not inspect native-tunnel starts" >&2
    return 1
  }
  if [[ "$count" != "$expected" ]]; then
    echo "Android Release $label expected one native-tunnel refresh ($before->$expected), observed ${count:-invalid}" >&2
    return 1
  fi
  ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT="$count"
  [[ "$(android_app_pid)" == "$expected_pid" ]] \
    && assert_single_android_app_process || {
      echo "Android Release $label changed the canonical app process" >&2
      return 1
    }
  echo "Android Release $label performed one in-process native-tunnel refresh ($before->$count)"
}

run_android_release_active_vpn_lifecycle_gate() {
  truthy "$ANDROID_LIFECYCLE_GATE" || return 0
  [[ "$ANDROID_LIFECYCLE_CYCLES" =~ ^[1-9][0-9]*$ \
    && "$ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS" =~ ^[0-9]+$ ]] \
    && (( ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS >= 10 )) || {
      echo "Android Release lifecycle requires >=10s background dwell" >&2
      return 1
  }
  local expected_pid cycle
  local lifecycle_ledger="$RUNTIME_STATE_RESULT_DIR/mobile-android-release-lifecycle-$$.tsv"
  : >"$lifecycle_ledger"
  expected_pid="$(android_app_pid)"
  android_release_assert_native_tunnel_unchanged lifecycle-start || return 1
  for cycle in $(seq 1 "$ANDROID_LIFECYCLE_CYCLES"); do
    "$ADB" -s "$serial" shell input keyevent KEYCODE_HOME || return 1
    sleep "$ANDROID_LIFECYCLE_BACKGROUND_DWELL_SECS"
    android_underlay_assert_process_and_vpn "$expected_pid" || return 1
    run_android_release_exit_network_probe \
      "release-background-cycle-$cycle" || return 1
    android_release_assert_native_tunnel_unchanged \
      "background cycle $cycle" || return 1
    start_main_activity
    wait_until 5 android_activity_resumed || return 1
    android_underlay_assert_process_and_vpn "$expected_pid" || return 1
    run_android_release_exit_network_probe \
      "release-foreground-cycle-$cycle" || return 1
    android_release_assert_native_tunnel_unchanged \
      "foreground cycle $cycle" || return 1
    printf '%s\t%s\t%s\n' \
      "$cycle" "$expected_pid" "$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT" \
      >>"$lifecycle_ledger"
  done
  echo "Android Release active VPN survived $ANDROID_LIFECYCLE_CYCLES real background/foreground cycles"
}

run_android_release_rapid_start_stop_gate() {
  truthy "$ANDROID_RAPID_START_STOP_GATE" || return 0
  local start_stop_ledger="$RUNTIME_STATE_RESULT_DIR/mobile-android-release-start-stop-$$.tsv"
  local expected_pid
  : >"$start_stop_ledger"
  # The enclosing black-box cycle already proves the initial start, exit,
  # stop, and stable direct path. This gate only needs to prove a reconnect.
  expected_pid="$(android_app_pid)"
  [[ "$expected_pid" =~ ^[1-9][0-9]*$ ]] \
    && assert_single_android_app_process || {
      echo "Android Release reconnect gate has no single canonical app process" >&2
      return 1
    }
  android_release_capture_native_tunnel_start_baseline || return 1
  vpn_cleanup_armed=1
  android_release_connect_ui || return 1
  android_release_pin_native_tunnel_start_count || return 1
  run_android_release_exit_network_probe start-stop-full-reconnect || return 1
  android_release_disconnect_ui || return 1
  android_release_wait_stable_quiescence \
    start-stop-full-reconnect "$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT" \
    || return 1
  vpn_cleanup_armed=0
  run_android_release_direct_network_probe start-stop-reconnect-cleanup 0 || return 1
  android_release_assert_native_tunnel_unchanged start-stop-final || return 1
  [[ "$(android_app_pid)" == "$expected_pid" ]] \
    && assert_single_android_app_process || {
      echo "Android Release reconnect gate changed the canonical app process" >&2
      return 1
    }
  printf 'semantic\t%s\t%s\n' \
    "$expected_pid" "$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT" \
    >>"$start_stop_ledger"
  echo "Android Release semantic start/stop/reconnect gate passed"
}

run_android_release_blackbox_cycle() {
  local direct_transition_pid
  android_release_ensure_network_ui || return 1
  android_release_disconnect_ui || return 1
  if ! truthy "$ANDROID_RELEASE_DNS_ONLY_CYCLE"; then
    run_android_release_direct_network_probe before-connect 0 || return 1
    configure_android_release_wireguard_ui || return 1
  fi
  if [[ -n "$EXIT_DNS_MODE" ]]; then
    configure_android_exit_dns_ui || return 1
  fi
  android_release_capture_native_tunnel_start_baseline || return 1
  vpn_cleanup_armed=1
  android_release_connect_ui || return 1
  android_release_pin_native_tunnel_start_count || return 1
  run_android_release_exit_network_probe wireguard-exit || return 1
  android_release_assert_native_tunnel_unchanged initial-exit || return 1
  run_android_underlay_network_change_gate || return 1
  run_android_release_active_vpn_lifecycle_gate || return 1
  android_release_assert_native_tunnel_unchanged \
    before-direct-selection || return 1
  if truthy "$SWITCH_TO_DIRECT_WHILE_CONNECTED"; then
    direct_transition_pid="$(android_app_pid)"
    [[ -n "$direct_transition_pid" ]] \
      && assert_single_android_app_process || return 1
    select_android_direct_ui || return 1
    wait_until "$VPN_START_WAIT_SECS" vpn_active || return 1
    run_android_release_direct_network_probe direct-while-connected 1 || return 1
    android_release_accept_single_native_tunnel_refresh \
      connected-direct "$direct_transition_pid" || return 1
  fi
  android_release_disconnect_ui || return 1
  android_release_wait_stable_quiescence \
    release-cycle-disconnect "$ANDROID_RELEASE_NATIVE_TUNNEL_START_COUNT" \
    || return 1
  vpn_cleanup_armed=0
  if ! truthy "$ANDROID_RELEASE_DNS_ONLY_CYCLE"; then
    run_android_release_direct_network_probe after-disconnect 0 || return 1
    android_release_assert_native_tunnel_unchanged \
      after-disconnect || return 1
  fi
  if truthy "$IDLE_CPU_GATE"; then
    run_android_idle_cpu_gate "Android Release foreground VPN-off" || return 1
    write_android_release_foreground_idle_receipt || return 1
  fi
  run_android_release_rapid_start_stop_gate || return 1
  assert_single_android_app_process
}
