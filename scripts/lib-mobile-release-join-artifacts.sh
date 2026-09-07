#!/usr/bin/env bash

# Exact artifact preparation and installation for the physical Release join
# gate. Callers provide ROOT, RESULT_DIR, IOS_DEVICE, ANDROID_SERIAL and ADB.

RELEASE_JOIN_ARTIFACTS_VALIDATED=0
RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=0
RELEASE_JOIN_DEVICE_MUTATED=0
RELEASE_JOIN_ANDROID_MUTATED=0
RELEASE_JOIN_IOS_CLEANUP_ARMED=0
RELEASE_JOIN_IOS_CLEANUP_BUNDLE_ID=""
RELEASE_JOIN_INSTALL_ANDROID=1
RELEASE_JOIN_INSTALL_IOS=1

release_join_reuse_artifacts() {
  case "${NVPN_RELEASE_JOIN_REUSE_ARTIFACTS:-0}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
    *) return 1 ;;
  esac
}

release_join_configure_install_modes() {
  local name env_name value normalized
  for name in ANDROID IOS; do
    env_name="NVPN_RELEASE_JOIN_INSTALL_${name}"
    value="${!env_name:-1}"
    case "$value" in
      1|true|TRUE|True|yes|YES|Yes|on|ON|On) normalized=1 ;;
      0|false|FALSE|False|no|NO|No|off|OFF|Off) normalized=0 ;;
      *)
        echo "Unsupported NVPN_RELEASE_JOIN_INSTALL_${name}=$value" >&2
        return 2
        ;;
    esac
    printf -v "RELEASE_JOIN_INSTALL_${name}" '%s' "$normalized"
  done
  if [[ "$RELEASE_JOIN_INSTALL_ANDROID" -eq 0 \
      || "$RELEASE_JOIN_INSTALL_IOS" -eq 0 ]] \
    && ! release_join_reuse_artifacts
  then
    echo "Disabled mobile join installation requires exact artifact reuse" >&2
    return 1
  fi
}

release_join_sha256() {
  shasum -a 256 "$1" | awk '{print $1}'
}

release_join_record_selected_devices() {
  local expected_name="${NVPN_EXPECTED_IOS_DEVICE_NAME:-}"
  local expected_android_model="${NVPN_EXPECTED_ANDROID_DEVICE_MODEL:-}"
  local details="$PRIVATE_DIR/ios-selected-device.json"
  local android_manufacturer android_model android_product
  [[ -n "$expected_name" ]] || {
    echo "Release join gate requires NVPN_EXPECTED_IOS_DEVICE_NAME" >&2
    return 1
  }
  [[ -n "$expected_android_model" ]] || {
    echo "Release join gate requires NVPN_EXPECTED_ANDROID_DEVICE_MODEL" >&2
    return 1
  }
  xcrun devicectl device info details \
    --device "$IOS_DEVICE" \
    --json-output "$details" \
    --quiet >/dev/null
  android_manufacturer="$(
    "${ADB[@]}" shell getprop ro.product.manufacturer | tr -d '\r'
  )"
  android_model="$("${ADB[@]}" shell getprop ro.product.model | tr -d '\r')"
  android_product="$("${ADB[@]}" shell getprop ro.product.name | tr -d '\r')"
  [[ -n "$android_model" && -n "$android_product" ]] || {
    echo "Selected Android phone did not report its model" >&2
    return 1
  }
  python3 - \
    "$details" \
    "$RESULT_DIR/selected-physical-devices.json" \
    "$expected_name" \
    "$expected_android_model" \
    "$android_manufacturer" \
    "$android_model" \
    "$android_product" <<'PY'
import json
import sys

(
    source,
    output,
    expected,
    expected_android_model,
    android_manufacturer,
    android_model,
    android_product,
) = sys.argv[1:]
payload = json.load(open(source, encoding="utf-8"))
result = payload.get("result", {})
device = result.get("deviceProperties", {})
hardware = result.get("hardwareProperties", {})
name = device.get("name")
marketing_name = hardware.get("marketingName")
product_type = hardware.get("productType") or hardware.get("thinningProductType")
hardware_model = hardware.get("hardwareModel")
if name != expected:
    raise SystemExit(
        f"selected iPhone name mismatch: expected {expected!r}, got {name!r}"
    )
if not isinstance(marketing_name, str) or not marketing_name.strip():
    raise SystemExit("selected iPhone did not report a marketing model")
if not isinstance(product_type, str) or not product_type.strip():
    raise SystemExit("selected iPhone did not report a product type")
if android_model != expected_android_model:
    raise SystemExit(
        "selected Android model mismatch: "
        f"expected {expected_android_model!r}, got {android_model!r}"
    )
receipt = {
    "explicitSelectionRequired": True,
    "ios": {
        "deviceName": name,
        "expectedDeviceNameMatched": True,
        "marketingName": marketing_name,
        "productType": product_type,
        "hardwareModel": hardware_model or "",
    },
    "android": {
        "manufacturer": android_manufacturer,
        "model": android_model,
        "expectedModelMatched": True,
        "productName": android_product,
    },
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(receipt, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

release_join_require_clean_fips() {
  : "${NVPN_FIPS_REPO_PATH:?Release join gate requires NVPN_FIPS_REPO_PATH}"
  [[ "${NVPN_EXPECTED_FIPS_GIT_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Release join gate requires an exact NVPN_EXPECTED_FIPS_GIT_SHA" >&2
    return 1
  }
  [[ -f "$NVPN_FIPS_REPO_PATH/crates/fips-core/Cargo.toml" ]] || {
    echo "Release join gate requires a FIPS source checkout" >&2
    return 1
  }
  RELEASE_JOIN_FIPS_SHA="$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse HEAD)"
  RELEASE_JOIN_FIPS_TREE="$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse HEAD^{tree})"
  [[ -z "$(git -C "$NVPN_FIPS_REPO_PATH" status --porcelain --untracked-files=all)" ]] || {
    echo "Release join gate refuses a dirty FIPS checkout" >&2
    return 1
  }
  if [[ "$RELEASE_JOIN_FIPS_SHA" != "$NVPN_EXPECTED_FIPS_GIT_SHA" ]]; then
    echo "Release join FIPS mismatch: expected $NVPN_EXPECTED_FIPS_GIT_SHA, got $RELEASE_JOIN_FIPS_SHA" >&2
    return 1
  fi
  RELEASE_JOIN_FIPS_VERSION="$(
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
  [[ "$RELEASE_JOIN_FIPS_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
    echo "Release join gate could not derive the exact FIPS package version" >&2
    return 1
  }
  export RELEASE_JOIN_FIPS_SHA RELEASE_JOIN_FIPS_TREE
  export RELEASE_JOIN_FIPS_VERSION
}

release_join_assert_fips_unchanged() {
  [[ "$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse HEAD)" == "$RELEASE_JOIN_FIPS_SHA" \
    && "$(git -C "$NVPN_FIPS_REPO_PATH" rev-parse HEAD^{tree})" == "$RELEASE_JOIN_FIPS_TREE" \
    && -z "$(git -C "$NVPN_FIPS_REPO_PATH" status --porcelain --untracked-files=all)" ]] || {
    echo "FIPS source changed while building Release join artifacts" >&2
    return 1
  }
}

release_join_require_device_mutation_allowed() {
  if release_join_reuse_artifacts \
    && [[ "$RELEASE_JOIN_ARTIFACTS_VALIDATED" -ne 1 ]]
  then
    echo "Strict Release join artifacts were not validated before device mutation" >&2
    return 1
  fi
  [[ "$RELEASE_JOIN_DEVICE_MUTATION_ALLOWED" -eq 1 ]] || {
    echo "Release join device mutation was not armed" >&2
    return 1
  }
}

release_join_assert_app_unchanged() {
  local expected_sha="$1" expected_tree="$2"
  assert_release_checkout_state \
    "$ROOT" "$expected_sha" "$expected_tree" \
    "Application Release artifact build" || {
    echo "Application candidate changed while building Release join artifacts" >&2
    return 1
  }
}

release_join_android_apksigner() {
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
  find "$sdk/build-tools" -type f -name apksigner 2>/dev/null \
    | sort -V \
    | tail -n 1
}

release_join_assert_one_android_package() {
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}" unexpected
  unexpected="$(
    "${ADB[@]}" shell pm list packages \
      | tr -d '\r' \
      | sed -n 's/^package://p' \
      | awk -v canonical="$package" \
          '$0 == "org.nostrvpn.app" || ($0 ~ /^fi\.siriusbusiness\.nvpn(\.|$)/ && $0 != canonical)'
  )"
  [[ -z "$unexpected" ]] || {
    echo "Parallel/stale Android nVPN package remains installed" >&2
    return 1
  }
  "${ADB[@]}" shell pm path "$package" >/dev/null 2>&1 || {
    echo "Canonical Android Release package is not installed" >&2
    return 1
  }
}

release_join_assert_one_android_process() {
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}" pids
  pids="$("${ADB[@]}" shell pidof "$package" 2>/dev/null | tr -d '\r' | xargs)"
  [[ -n "$pids" && "$(wc -w <<<"$pids" | tr -d ' ')" == 1 ]] || {
    echo "Android Release gate requires exactly one canonical app process; got: ${pids:-none}" >&2
    return 1
  }
}

release_join_prepare_android_release() {
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"
  local apk="$ROOT/android/app/build/outputs/apk/release/app-release.apk"
  local apksigner remote_path pulled apk_sha installed_sha cert_sha cert_sha_lower app_sha app_tree
  local expected_android_cert="${NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256:-}"
  local preexisting_package=false replacement_install=false
  if release_join_reuse_artifacts; then
    [[ "$RELEASE_JOIN_ARTIFACTS_VALIDATED" -eq 1 \
      && -f "$RELEASE_JOIN_ANDROID_APK" ]] || {
      echo "Strict Android Release artifact was not prevalidated" >&2
      return 1
    }
    apk="$RELEASE_JOIN_ANDROID_APK"
    app_sha="$RELEASE_JOIN_ANDROID_APP_SHA"
    app_tree="$RELEASE_JOIN_ANDROID_APP_TREE"
    cert_sha_lower="$RELEASE_JOIN_ANDROID_SIGNER_SHA"
  else
    for name in ANDROID_KEYSTORE_PATH ANDROID_KEYSTORE_PASSWORD ANDROID_KEY_ALIAS ANDROID_KEY_PASSWORD; do
      [[ -n "${!name:-}" ]] || {
        echo "Release join gate requires $name" >&2
        return 1
      }
    done
    [[ -f "$ANDROID_KEYSTORE_PATH" ]] || {
      echo "Android release keystore does not exist" >&2
      return 1
    }
    app_sha="$(git -C "$ROOT" rev-parse HEAD)"
    app_tree="$(git -C "$ROOT" rev-parse HEAD^{tree})"
    NVPN_IOS_RUST_PROFILE=release \
      NVPN_BUILD_GIT_SHA="$app_sha" \
      NVPN_FIPS_REPO_PATH="$NVPN_FIPS_REPO_PATH" \
      NVPN_ANDROID_PACKAGE="$package" \
      "$ROOT/tools/run-android" release
    [[ -f "$apk" ]] || {
      echo "Android Release APK was not built" >&2
      return 1
    }
    apksigner="$(release_join_android_apksigner)"
    [[ -x "$apksigner" ]] || {
      echo "Android apksigner is unavailable" >&2
      return 1
    }
    "$apksigner" verify "$apk" >/dev/null
    cert_sha="$(
      "$apksigner" verify --print-certs "$apk" \
        | awk 'index($0, "certificate SHA-256 digest: ") { sub(/^.*certificate SHA-256 digest: /, ""); print; exit }' \
        | head -n 1
    )"
    [[ "$cert_sha" =~ ^[0-9A-Fa-f]{64}$ ]] || {
      echo "Android Release APK has no signer certificate receipt" >&2
      return 1
    }
    cert_sha_lower="$(printf '%s' "$cert_sha" | tr '[:upper:]' '[:lower:]')"
    expected_android_cert="$(
      printf '%s' "$expected_android_cert" \
        | tr -d ':[:space:]' \
        | tr '[:upper:]' '[:lower:]'
    )"
    [[ "$expected_android_cert" =~ ^[0-9a-f]{64}$ ]] || {
      echo "Release join gate requires NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256" >&2
      return 1
    }
    [[ "$cert_sha_lower" == "$expected_android_cert" ]] || {
      echo "Android Release APK was not signed by the expected company key" >&2
      return 1
    }
  fi

  release_join_require_device_mutation_allowed || return 1
  RELEASE_JOIN_DEVICE_MUTATED=1
  # shellcheck disable=SC2034 # read by the caller's Android cleanup trap
  RELEASE_JOIN_ANDROID_MUTATED=1
  if "${ADB[@]}" shell pm path "$package" >/dev/null 2>&1; then
    preexisting_package=true
  fi
  if [[ "$RELEASE_JOIN_INSTALL_ANDROID" -eq 1 ]]; then
    # A fresh phone needs an initial install before proving in-place replacement.
    if [[ "$preexisting_package" != true ]]; then
      "${ADB[@]}" install -r "$apk" >/dev/null
      release_join_assert_one_android_package
    fi
    "${ADB[@]}" install -r "$apk" >/dev/null
    release_join_assert_one_android_package
    replacement_install=true
  elif [[ "$preexisting_package" != true ]]; then
    echo "Exact Android Release package is not already installed" >&2
    return 1
  fi
  remote_path="$(
    "${ADB[@]}" shell pm path "$package" \
      | tr -d '\r' \
      | sed -n 's/^package://p' \
      | head -n 1
  )"
  pulled="$(mktemp "${TMPDIR:-/tmp}/nvpn-release-installed.XXXXXX")"
  "${ADB[@]}" pull "$remote_path" "$pulled" >/dev/null
  apk_sha="$(release_join_sha256 "$apk")"
  installed_sha="$(release_join_sha256 "$pulled")"
  rm -f "$pulled"
  [[ "$apk_sha" == "$installed_sha" ]] || {
    echo "Installed Android package bytes differ from the Release APK" >&2
    return 1
  }
  if "${ADB[@]}" shell dumpsys package "$package" \
      | sed -n '/^[[:space:]]*flags=/{p;q;}' \
      | grep -qw DEBUGGABLE; then
    echo "Installed Android app is debuggable" >&2
    return 1
  fi
  "${ADB[@]}" shell am force-stop "$package"
  "${ADB[@]}" shell monkey -p "$package" -c android.intent.category.LAUNCHER 1 >/dev/null
  sleep 1
  release_join_assert_one_android_process
  release_join_assert_fips_unchanged
  if release_join_reuse_artifacts; then
    release_join_assert_app_unchanged "$APP_GIT_SHA" "$APP_GIT_TREE"
  else
    release_join_assert_app_unchanged "$app_sha" "$app_tree"
  fi

  RELEASE_JOIN_ANDROID_APK="$apk"
  RELEASE_JOIN_ANDROID_APK_SHA="$apk_sha"
  export RELEASE_JOIN_ANDROID_APK RELEASE_JOIN_ANDROID_APK_SHA
  python3 - \
    "$RESULT_DIR/android-release-install.json" \
    "$apk_sha" "$cert_sha_lower" "$app_sha" "$app_tree" \
    "$RELEASE_JOIN_FIPS_SHA" "$RELEASE_JOIN_FIPS_TREE" "$package" \
    "$preexisting_package" "$replacement_install" <<'PY'
import json
import sys

path, apk, cert, app, app_tree, fips, fips_tree, package, preexisting, replacement = sys.argv[1:]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "artifact": "Android Release APK",
            "apkSha256": apk,
            "installedApkSha256": apk,
            "signerCertificateSha256": cert,
            "appGitSha": app,
            "appGitTree": app_tree,
            "fipsGitSha": fips,
            "fipsGitTree": fips_tree,
            "package": package,
            "preexistingCanonicalPackage": preexisting == "true",
            "replacementInstall": replacement == "true",
            "replacementInstallVerified": replacement == "true",
            "installedArtifactVerified": True,
            "debuggable": False,
            "canonicalPackageCount": 1,
            "canonicalProcessCount": 1,
        },
        handle,
        indent=2,
        sort_keys=True,
    )
    handle.write("\n")
PY
}

release_join_ios_profile_value() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null
}

release_join_codesign_team() {
  codesign -dvv "$1" 2>&1 \
    | sed -n 's/^TeamIdentifier=//p' \
    | head -n 1
}

release_join_codesign_certificate_sha256() {
  local bundle="$1" certificate_dir prefix certificate
  certificate_dir="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-signing-cert.XXXXXX")"
  prefix="$certificate_dir/certificate"
  codesign -d --extract-certificates="$prefix" "$bundle" >/dev/null 2>&1
  certificate="${prefix}0"
  [[ -f "$certificate" ]] || {
    rm -rf "$certificate_dir"
    return 1
  }
  release_join_sha256 "$certificate"
  rm -rf "$certificate_dir"
}

release_join_codesign_cdhash() {
  codesign -dvvv "$1" 2>&1 \
    | sed -n 's/^CDHash=//p' \
    | head -n 1 \
    | tr '[:upper:]' '[:lower:]'
}

release_join_expose_ios_fixture_documents() {
  local app="$1"
  local info="$app/Info.plist"
  local production_info="$ROOT/ios/Info.plist"
  local certificate_dir certificate_prefix certificate identity
  [[ -f "$info" ]] || {
    echo "iOS join-test app Info.plist is unavailable" >&2
    return 1
  }
  for key in UIFileSharingEnabled LSSupportsOpeningDocumentsInPlace; do
    if plutil -extract "$key" raw "$production_info" >/dev/null 2>&1; then
      echo "Production iOS Info.plist exposes test fixture file sharing" >&2
      return 1
    fi
  done
  certificate_dir="$(mktemp -d "${PRIVATE_DIR:-${TMPDIR:-/tmp}}/nvpn-ios-runner-cert.XXXXXX")" \
    || return 1
  certificate_prefix="$certificate_dir/certificate"
  if ! codesign -d --extract-certificates="$certificate_prefix" "$app" \
      >/dev/null 2>&1; then
    rm -rf "$certificate_dir"
    echo "Could not read the iOS join-test app signing identity" >&2
    return 1
  fi
  certificate="${certificate_prefix}0"
  identity="$(shasum -a 1 "$certificate" 2>/dev/null | awk '{print $1}')"
  if [[ ! "$identity" =~ ^[0-9a-fA-F]{40}$ ]]; then
    rm -rf "$certificate_dir"
    echo "iOS join-test app has no reusable signing identity" >&2
    return 1
  fi

  # This app is a separately receipted join-test variant. Production keeps
  # file sharing disabled; the retained XCTest runner remains untouched.
  plutil -replace CFBundleDisplayName \
    -string "Nostr VPN Test Files" "$info"
  plutil -replace UIFileSharingEnabled -bool YES "$info"
  plutil -replace LSSupportsOpeningDocumentsInPlace -bool YES "$info"
  if ! codesign --force --sign "$identity" \
      --preserve-metadata=identifier,entitlements,requirements,flags,runtime \
      "$app" >/dev/null 2>&1; then
    rm -rf "$certificate_dir"
    echo "Could not re-sign the iOS join-test app after enabling fixture storage" >&2
    return 1
  fi
  rm -rf "$certificate_dir"
  codesign --verify --deep --strict "$app" >/dev/null 2>&1 \
    && [[ "$(plutil -extract CFBundleDisplayName raw "$info")" \
      == "Nostr VPN Test Files" ]] \
    && [[ "$(plutil -extract UIFileSharingEnabled raw "$info")" == true ]] \
    && [[ "$(plutil -extract LSSupportsOpeningDocumentsInPlace raw "$info")" \
      == true ]] || {
    echo "iOS join-test app fixture storage verification failed" >&2
    return 1
  }
}

release_join_ios_tree_receipt() {
  python3 - "$1" "$2" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
entries = []
for path in sorted(item for item in root.rglob("*") if item.is_file()):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    entries.append({"path": str(path.relative_to(root)), "sha256": digest, "size": path.stat().st_size})
canonical = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()
receipt = {
    "bundleManifestSha256": hashlib.sha256(canonical).hexdigest(),
    "files": entries,
}
output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(receipt["bundleManifestSha256"])
PY
}

release_join_prepare_ios_profiles() {
  local udid="$1" profile_dir="$RESULT_DIR/ios-signing"
  local profile_env="$profile_dir/provisioning.env"
  local company_signing signing_identity signing_team
  declare -F ios_release_network_company_signing >/dev/null || {
    echo "Release join gate cannot resolve the pinned company signer" >&2
    return 1
  }
  company_signing="$(
    ios_release_network_company_signing \
      "${NVPN_IOS_EXPECTED_SIGNER_ORGANIZATION:-Sirius Business Oy}" \
      "${NVPN_EXPECTED_IOS_DISTRIBUTION_CERT_SHA256:-}"
  )" || return 1
  signing_identity="${company_signing%%|*}"
  signing_team="${company_signing#*|}"
  [[ "$signing_team" == "${NVPN_EXPECTED_IOS_DISTRIBUTION_TEAM_ID:-}" ]] || {
    echo "Release join signer belongs to the wrong company team" >&2
    return 1
  }
  mkdir -p "$profile_dir"
  NVPN_IOS_PROFILE_TYPE=IOS_APP_ADHOC \
    NVPN_IOS_PROFILE_NAME="Nostr VPN Ad Hoc Release join gate" \
    NVPN_IOS_PACKET_TUNNEL_PROFILE_NAME="Nostr VPN Ad Hoc Release join tunnel" \
    NVPN_IOS_CODE_SIGN_IDENTITY="$signing_identity" \
    NVPN_IOS_DEVICE_UDIDS="$udid" \
    NVPN_IOS_PROFILES_ENV_PATH="$profile_env" \
    "$ROOT/scripts/ios-profiles" ensure >"$profile_dir/profile-setup.log" 2>&1
  # shellcheck disable=SC1090
  source "$profile_env"
  : "${NVPN_IOS_CODE_SIGN_IDENTITY:?Ad Hoc signing identity missing}"
  : "${NVPN_IOS_PROVISIONING_PROFILE_UUID:?Ad Hoc app profile missing}"
  : "${NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID:?Ad Hoc tunnel profile missing}"
  [[ "$NVPN_IOS_CODE_SIGN_IDENTITY" == "$signing_identity" ]] || {
    echo "Release join profile selection changed the pinned company signer" >&2
    return 1
  }
}

release_join_install_ios_release() {
  local app_path="$1" app_sha="$2" app_tree="$3" manifest_sha="$4"
  local team_hash="$5" app_cert="$6" derived="$7" udid="$8"
  local bundle="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
  local installed_json="$RESULT_DIR/ios-installed-apps.json"
  local installed_receipt="$RESULT_DIR/ios-release-install.json"
  local runner="$derived/Build/Products/Release-iphoneos/NostrVpnIosUITests-Runner.app"
  local runner_tree
  local replacement_install=false prior_install_receipt=""
  release_join_require_device_mutation_allowed || return 1
  RELEASE_JOIN_DEVICE_MUTATED=1
  # Installing the exact verified bundle in place replaces its executable but
  # preserves the app container and the user's already-approved VPN manager.
  # Uninstalling here needlessly revokes that approval and forces a passcode
  # prompt before every physical gate retry.
  [[ -d "$runner" ]] || {
    echo "Exact iOS UI runner is unavailable" >&2
    return 1
  }
  release_join_arm_ios_disconnect_cleanup "$app_path" "$derived" "$udid" \
    || return 1
  runner_tree="$(
    python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" tree-sha "$runner"
  )" || return 1
  if [[ "$RELEASE_JOIN_INSTALL_IOS" -eq 1 ]]; then
    # The packet gate has already installed and receipted this exact runner.
    # Changing only the QR app variant must not replace it or revoke its trust.
    if [[ -n "${NVPN_MOBILE_IOS_INSTALLED_RUNNER_RECEIPT:-}" ]]; then
      [[ "$RELEASE_JOIN_ARTIFACTS_VALIDATED" -eq 1 ]] || return 1
      IOS_BUNDLE_ID="$bundle" ios_release_network_require_installed_reuse \
        "$app_path" "$runner" "$NVPN_RELEASE_JOIN_IOS_RECEIPT" \
        "$NVPN_MOBILE_IOS_INSTALLED_RUNNER_RECEIPT" "$runner_tree" \
        "$(printf %s "$udid" | shasum -a 256 | awk '{print $1}')" \
        "$(release_join_sha256 "$RELEASE_JOIN_IOS_XCTESTRUN")" \
        "$(python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" \
          tree-sha "$derived/Build/Products")" || return 1
    fi
    if ! xcrun devicectl device install app \
        --device "$IOS_DEVICE" "$app_path" --quiet
    then
      echo "Exact iOS app installation failed" >&2
      return 1
    fi
    if [[ -z "${NVPN_MOBILE_IOS_INSTALLED_RUNNER_RECEIPT:-}" ]] \
      && ! xcrun devicectl device install app \
        --device "$IOS_DEVICE" "$runner" --quiet
    then
      echo "Exact iOS runner installation failed" >&2
      return 1
    fi
    replacement_install=true
  else
    prior_install_receipt="${NVPN_RELEASE_JOIN_IOS_INSTALL_RECEIPT:-}"
    [[ "$RELEASE_JOIN_ARTIFACTS_VALIDATED" -eq 1 \
      && -s "$prior_install_receipt" ]] || {
      echo "iOS no-install reuse requires its device-bound runner install receipt" >&2
      return 1
    }
  fi
  if ! xcrun devicectl device info apps \
      --device "$IOS_DEVICE" \
      --json-output "$installed_json" \
      --quiet
  then
    echo "Installed iOS app/runner inventory failed" >&2
    return 1
  fi
  if ! python3 - \
    "$installed_json" "$installed_receipt" "$bundle" "$manifest_sha" \
    "$app_sha" "$app_tree" "$RELEASE_JOIN_FIPS_SHA" \
    "$RELEASE_JOIN_FIPS_TREE" "$RELEASE_JOIN_FIPS_VERSION" \
    "$team_hash" "$app_cert" "$app_path/Info.plist" \
    "$runner/Info.plist" "$replacement_install" \
    "$prior_install_receipt" "$udid" "$runner_tree" <<'PY'
import hashlib
import json
import plistlib
import sys

(
    source,
    output,
    bundle,
    manifest,
    app,
    app_tree,
    fips,
    fips_tree,
    fips_version,
    team_hash,
    cert,
    app_plist_path,
    runner_plist_path,
    replacement,
    prior_install_receipt_path,
    udid,
    runner_tree,
) = sys.argv[1:]
payload = json.load(open(source, encoding="utf-8"))
apps = []


def visit(value):
    if isinstance(value, dict):
        if isinstance(value.get("bundleIdentifier"), str):
            apps.append(value)
        for child in value.values():
            visit(child)
    elif isinstance(value, list):
        for child in value:
            visit(child)


visit(payload)

def exact_installed(identifier, plist_path):
    matches = [item for item in apps if item.get("bundleIdentifier") == identifier]
    if len(matches) != 1:
        raise SystemExit(f"expected one installed iOS app for {identifier}, found {len(matches)}")
    with open(plist_path, "rb") as handle:
        info = plistlib.load(handle)
    if info.get("CFBundleIdentifier") != identifier:
        raise SystemExit(f"local iOS bundle identity mismatch: {identifier}")
    expected = (
        str(info.get("CFBundleVersion", "")),
        str(info.get("CFBundleShortVersionString", "")),
    )
    actual = (str(matches[0].get("bundleVersion", "")), str(matches[0].get("version", "")))
    if not all(expected) or actual != expected:
        raise SystemExit(f"installed iOS bundle version mismatch: {identifier}")
    return actual

app_version, app_short_version = exact_installed(bundle, app_plist_path)
exact_installed(bundle + ".UITests.xctrunner", runner_plist_path)
if replacement != "true":
    prior = json.load(open(prior_install_receipt_path, encoding="utf-8"))
    expected_prior = {
        "receiptSchema": 1,
        "artifactType": "installed iOS Release app and XCTest runner",
        "appGitSha": app,
        "appGitTree": app_tree,
        "fipsGitSha": fips,
        "fipsGitTree": fips_tree,
        "bundleManifestSha256": manifest,
        "runnerBundleTreeSha256": runner_tree,
        "signerCertificateSha256": cert,
        "selectedPhysicalDeviceIdentifierSha256": hashlib.sha256(
            udid.encode()
        ).hexdigest(),
        "bundleIdentifier": bundle,
        "installedVersion": app_version,
        "installedShortVersion": app_short_version,
    }
    for key, value in expected_prior.items():
        if prior.get(key) != value:
            raise SystemExit(f"device-bound iOS receipt mismatch: {key}")
receipt = {
    "receiptSchema": 1,
    "artifactType": "installed iOS Release app and XCTest runner",
    "artifact": "iOS Ad Hoc Release app",
    "bundleIdentifier": bundle,
    "bundleManifestSha256": manifest,
    "runnerBundleTreeSha256": runner_tree,
    "selectedPhysicalDeviceIdentifierSha256": hashlib.sha256(
        udid.encode()
    ).hexdigest(),
    "installedVersion": app_version,
    "installedShortVersion": app_short_version,
    "appGitSha": app,
    "appGitTree": app_tree,
    "fipsGitSha": fips,
    "fipsGitTree": fips_tree,
    "fipsCoreVersion": fips_version,
    "signingTeamSha256": team_hash,
    "signerCertificateSha256": cert,
    "appAndPacketTunnelSignerMatch": True,
    "distribution": "Ad Hoc",
    "configuration": "Release",
    "debugAutomation": False,
    "installedBundleCount": 1,
    "installedArtifactVerified": True,
    "replacementInstall": replacement == "true",
}

with open(output, "w", encoding="utf-8") as handle:
    json.dump(receipt, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
  then
    rm -f "$installed_receipt"
    echo "Installed iOS app/runner identity validation failed" >&2
    return 1
  fi
  RELEASE_JOIN_IOS_DERIVED_DATA="$derived"
  RELEASE_JOIN_IOS_APP_PATH="$app_path"
  RELEASE_JOIN_IOS_UDID="$udid"
  export RELEASE_JOIN_IOS_DERIVED_DATA RELEASE_JOIN_IOS_APP_PATH
  export RELEASE_JOIN_IOS_UDID
}

release_join_arm_ios_disconnect_cleanup() {
  local app="$1" derived="$2" udid="$3" private_root
  [[ -s "$RELEASE_JOIN_IOS_XCTESTRUN" ]] || {
    echo "iOS disconnect cleanup requires the exact XCTest plan" >&2
    return 1
  }
  [[ "$RELEASE_JOIN_IOS_CLEANUP_ARMED" -eq 0 ]] || return 0
  private_root="${PRIVATE_DIR:-${TMPDIR:-/tmp}}"
  IOS_RELEASE_NETWORK_SIGNING_DIR="$(
    mktemp -d "$private_root/nvpn-ios-release-signing.join-cleanup.XXXXXX"
  )" || return 1
  IOS_RELEASE_NETWORK_ACTIVE_PGID_FILE="$IOS_RELEASE_NETWORK_SIGNING_DIR/active-xcode.pgid"
  IOS_RELEASE_NETWORK_DEVICE="$udid"
  IOS_RELEASE_NETWORK_DESTINATION="platform=iOS,id=$udid,arch=arm64"
  IOS_RELEASE_NETWORK_DERIVED_DATA="$derived"
  IOS_RELEASE_NETWORK_XCTESTRUN="$RELEASE_JOIN_IOS_XCTESTRUN"
  IOS_RELEASE_NETWORK_FROZEN_APP="$app"
  RELEASE_JOIN_IOS_CLEANUP_BUNDLE_ID="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
  IOS_RELEASE_NETWORK_EXACT_RUNNER_READY=1
  IOS_RELEASE_NETWORK_PREPARED=1
  NVPN_MOBILE_IOS_RELEASE_APP_PATH="$app"
  export NVPN_MOBILE_IOS_RELEASE_APP_PATH
  RELEASE_JOIN_IOS_CLEANUP_ARMED=1
}

release_join_cleanup_ios_network_state() {
  local quarantine="${RELEASE_JOIN_IOS_QUARANTINE:?missing iOS quarantine path}"
  [[ "$RELEASE_JOIN_IOS_CLEANUP_ARMED" -eq 1 ]] || return 0
  if IOS_BUNDLE_ID="${RELEASE_JOIN_IOS_CLEANUP_BUNDLE_ID:?missing scoped iOS cleanup bundle}" \
      ios_release_network_disconnect_cleanup; then
    rm -f "$quarantine"
    return 0
  fi
  printf '%s\n' 'PacketTunnel/direct Internet cleanup was not proven.' >"$quarantine"
  echo "iOS device quarantined because PacketTunnel-off/direct Internet is unproven" >&2
  return 1
}

release_join_prepare_ios_release() {
  local bundle="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
  local tunnel="$bundle.PacketTunnel"
  local group="group.$bundle.shared"
  local team="${NVPN_IOS_TEAM_ID:?Release join gate requires NVPN_IOS_TEAM_ID}"
  local expected_team="${NVPN_EXPECTED_IOS_DISTRIBUTION_TEAM_ID:-}"
  local expected_cert="${NVPN_EXPECTED_IOS_DISTRIBUTION_CERT_SHA256:-}"
  local udid app_path app_binary tunnel_app tunnel_binary profile_plist tunnel_profile_plist
  local app_signed_team tunnel_signed_team app_cert tunnel_cert team_hash
  local app_cdhash tunnel_cdhash device_identifier_sha variant_receipt
  local derived="$RESULT_DIR/ios-derived-data"
  local app_sha app_tree manifest_sha
  if release_join_reuse_artifacts; then
    [[ "$RELEASE_JOIN_ARTIFACTS_VALIDATED" -eq 1 \
      && -d "$RELEASE_JOIN_IOS_APP_PATH" \
      && -d "$RELEASE_JOIN_IOS_DERIVED_DATA" \
      && -s "$RELEASE_JOIN_IOS_XCTESTRUN" ]] || {
      echo "Strict iOS Release artifact was not prevalidated" >&2
      return 1
    }
    team_hash="$(
      printf '%s' "$expected_team" | shasum -a 256 | awk '{print $1}'
    )"
    release_join_install_ios_release \
      "$RELEASE_JOIN_IOS_APP_PATH" \
      "$RELEASE_JOIN_IOS_APP_SHA" \
      "$RELEASE_JOIN_IOS_APP_TREE" \
      "$RELEASE_JOIN_IOS_BUNDLE_MANIFEST_SHA" \
      "$team_hash" \
      "$RELEASE_JOIN_IOS_APP_CERT" \
      "$RELEASE_JOIN_IOS_DERIVED_DATA" \
      "$RELEASE_JOIN_IOS_UDID"
    return
  fi
  : "${NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT:?Release join gate requires the production iOS receipt}"
  [[ -f "$NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT" \
    && ! -L "$NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT" ]] || {
    echo "Release join gate requires a regular production iOS receipt" >&2
    return 1
  }
  [[ -n "$expected_team" && "$team" == "$expected_team" ]] || {
    echo "NVPN_IOS_TEAM_ID is not the explicitly expected company distribution team" >&2
    return 1
  }
  expected_cert="$(
    printf '%s' "$expected_cert" \
      | tr -d ':[:space:]' \
      | tr '[:upper:]' '[:lower:]'
  )"
  [[ "$expected_cert" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Release join gate requires NVPN_EXPECTED_IOS_DISTRIBUTION_CERT_SHA256" >&2
    return 1
  }
  udid="$(resolve_physical_ios_udid "$IOS_DEVICE")"
  release_join_prepare_ios_profiles "$udid"
  app_sha="$(git -C "$ROOT" rev-parse HEAD)"
  app_tree="$(git -C "$ROOT" rev-parse HEAD^{tree})"

  export NVPN_IOS_BUNDLE_ID="$bundle"
  export NVPN_IOS_PACKET_TUNNEL_BUNDLE_ID="$tunnel"
  export NVPN_IOS_APP_GROUP_IDENTIFIER="$group"
  NVPN_IOS_RUST_PROFILE=release \
    NVPN_BUILD_GIT_SHA="$app_sha" \
    NVPN_FIPS_REPO_PATH="$NVPN_FIPS_REPO_PATH" \
    "$ROOT/tools/run-ios" xcframework
  "$ROOT/tools/run-ios" project
  xcodebuild \
    -quiet \
    -allowProvisioningUpdates \
    -project "$ROOT/ios/NostrVpnIos.xcodeproj" \
    -scheme NostrVpnIos \
    -configuration Release \
    -derivedDataPath "$derived" \
    -destination "platform=iOS,id=$udid" \
    DEVELOPMENT_TEAM="$team" \
    NVPN_IOS_CODE_SIGN_IDENTITY="$NVPN_IOS_CODE_SIGN_IDENTITY" \
    NVPN_IOS_PROVISIONING_PROFILE_UUID="$NVPN_IOS_PROVISIONING_PROFILE_UUID" \
    NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID="$NVPN_IOS_PACKET_TUNNEL_PROVISIONING_PROFILE_UUID" \
    NVPN_BUILD_GIT_SHA="$app_sha" \
    'OTHER_SWIFT_FLAGS=$(inherited) -DNVPN_RELEASE_JOIN_TESTING' \
    build-for-testing
  RELEASE_JOIN_IOS_XCTESTRUN="$(
    select_generated_ios_release_xctestrun \
      "$derived/Build/Products" "iOS Release join build"
  )" || return 1
  export RELEASE_JOIN_IOS_XCTESTRUN

  app_path="$derived/Build/Products/Release-iphoneos/Nostr VPN.app"
  [[ -d "$app_path" ]] || {
    echo "iOS Release app was not built for testing" >&2
    return 1
  }
  release_join_expose_ios_fixture_documents "$app_path" || return 1
  app_binary="$app_path/Nostr VPN"
  tunnel_app="$app_path/PlugIns/Nostr VPN Tunnel.appex"
  tunnel_binary="$tunnel_app/Nostr VPN Tunnel"
  codesign --verify --deep --strict "$app_path"
  codesign --verify --strict "$tunnel_app"
  profile_plist="$RESULT_DIR/ios-signing/embedded-profile.plist"
  tunnel_profile_plist="$RESULT_DIR/ios-signing/embedded-tunnel-profile.plist"
  security cms -D -i "$app_path/embedded.mobileprovision" >"$profile_plist"
  security cms -D -i "$tunnel_app/embedded.mobileprovision" >"$tunnel_profile_plist"
  [[ "$(release_join_ios_profile_value "$profile_plist" ProvisionsAllDevices)" != true ]]
  /usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" "$profile_plist" \
    | grep -Fq "$udid"
  [[ "$(release_join_ios_profile_value "$tunnel_profile_plist" ProvisionsAllDevices)" != true ]]
  /usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" "$tunnel_profile_plist" \
    | grep -Fq "$udid"
  [[ "$(release_join_ios_profile_value "$profile_plist" Entitlements:get-task-allow)" != true ]]
  [[ "$(release_join_ios_profile_value "$tunnel_profile_plist" Entitlements:get-task-allow)" != true ]]
  [[ "$(release_join_ios_profile_value "$profile_plist" TeamIdentifier:0)" == "$team" ]]
  [[ "$(release_join_ios_profile_value "$profile_plist" Entitlements:application-identifier)" == "$team.$bundle" ]]
  [[ "$(release_join_ios_profile_value "$tunnel_profile_plist" TeamIdentifier:0)" == "$team" ]]
  [[ "$(release_join_ios_profile_value "$tunnel_profile_plist" Entitlements:application-identifier)" == "$team.$tunnel" ]]
  app_signed_team="$(release_join_codesign_team "$app_path")"
  tunnel_signed_team="$(release_join_codesign_team "$tunnel_app")"
  [[ "$app_signed_team" == "$expected_team" \
    && "$tunnel_signed_team" == "$expected_team" ]] || {
    echo "iOS app or PacketTunnel was signed by the wrong team" >&2
    return 1
  }
  app_cert="$(release_join_codesign_certificate_sha256 "$app_path")"
  tunnel_cert="$(release_join_codesign_certificate_sha256 "$tunnel_app")"
  [[ "$app_cert" == "$expected_cert" && "$tunnel_cert" == "$expected_cert" ]] || {
    echo "iOS app or PacketTunnel was signed by the wrong distribution certificate" >&2
    return 1
  }
  team_hash="$(printf '%s' "$expected_team" | shasum -a 256 | awk '{print $1}')"
  if strings "$app_binary" "$tunnel_binary" \
      | grep -Eq 'nvpn-debug|DEBUG_ACTION|SCREENSHOT_FIXTURE'; then
    echo "iOS Release binary contains debug automation entry points" >&2
    return 1
  fi
  manifest_sha="$(
    release_join_ios_tree_receipt \
      "$app_path" "$RESULT_DIR/ios-release-bundle-manifest.json"
  )"
  release_join_assert_fips_unchanged
  release_join_assert_app_unchanged "$app_sha" "$app_tree"
  app_cdhash="$(release_join_codesign_cdhash "$app_path")"
  tunnel_cdhash="$(release_join_codesign_cdhash "$tunnel_app")"
  [[ "$app_cdhash" =~ ^[0-9a-f]{40}$ \
    && "$tunnel_cdhash" =~ ^[0-9a-f]{40}$ ]] || {
    echo "iOS join-test variant has invalid code-directory hashes" >&2
    return 1
  }
  device_identifier_sha="$(printf '%s' "$udid" | shasum -a 256 | awk '{print $1}')"
  variant_receipt="$RESULT_DIR/ios-join-test-variant.json"
  python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" \
    create-ios-join-variant \
    --receipt "$variant_receipt" \
    --production-receipt "$NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT" \
    --app "$app_path" \
    --derived-data "$derived" \
    --xctestrun "$RELEASE_JOIN_IOS_XCTESTRUN" \
    --app-head "$app_sha" \
    --app-tree "$app_tree" \
    --fips-head "$RELEASE_JOIN_FIPS_SHA" \
    --fips-tree "$RELEASE_JOIN_FIPS_TREE" \
    --fips-version "$RELEASE_JOIN_FIPS_VERSION" \
    --bundle "$bundle" \
    --signer-sha "$app_cert" \
    --app-cdhash "$app_cdhash" \
    --tunnel-cdhash "$tunnel_cdhash" \
    --device-identifier-sha "$device_identifier_sha" || return 1
  NVPN_RELEASE_JOIN_IOS_RECEIPT="$variant_receipt"
  RELEASE_JOIN_IOS_APP_SHA="$app_sha"
  RELEASE_JOIN_IOS_APP_TREE="$app_tree"
  RELEASE_JOIN_IOS_APP_CERT="$app_cert"
  RELEASE_JOIN_IOS_APP_TREE_SHA="$(
    python3 - "$variant_receipt" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["appBundleTreeSha256"])
PY
  )"
  export NVPN_RELEASE_JOIN_IOS_RECEIPT RELEASE_JOIN_IOS_APP_SHA
  export RELEASE_JOIN_IOS_APP_TREE RELEASE_JOIN_IOS_APP_CERT
  export RELEASE_JOIN_IOS_APP_TREE_SHA
  release_join_install_ios_release \
    "$app_path" "$app_sha" "$app_tree" "$manifest_sha" \
    "$team_hash" "$app_cert" "$derived" "$udid"
}

release_join_restart_ios_in_place() {
  local bundle="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
  release_join_require_device_mutation_allowed || return 1
  [[ -d "$RELEASE_JOIN_IOS_APP_PATH" ]] || {
    echo "Exact iOS Release artifact is unavailable" >&2
    return 1
  }
  RELEASE_JOIN_DEVICE_MUTATED=1
  # Restart the installed binary in place while retaining its VPN approval and
  # container. Each phase proves isolation by creating a fresh network ID;
  # reinstalling cannot improve that isolation and triggers passcode UI.
  xcrun devicectl device process launch \
    --device "$IOS_DEVICE" \
    --terminate-existing \
    --no-activate \
    "$bundle" >/dev/null
}

release_join_assert_one_ios_process() {
  local processes="$RESULT_DIR/ios-processes-final.json"
  xcrun devicectl device info processes \
    --device "$IOS_DEVICE" \
    --json-output "$processes" \
    --quiet
  python3 - "$processes" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
matches = []

def visit(value):
    if isinstance(value, dict):
        executable = str(value.get("executable", ""))
        if executable.endswith("/Nostr%20VPN.app/Nostr%20VPN") or executable.endswith("/Nostr VPN.app/Nostr VPN"):
            matches.append(value)
        for child in value.values():
            visit(child)
    elif isinstance(value, list):
        for child in value:
            visit(child)

visit(payload)
if len(matches) != 1:
    raise SystemExit(f"expected one iOS Nostr VPN app process, found {len(matches)}")
PY
}

release_join_launch_ios_release() {
  local bundle="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
  xcrun devicectl device process launch \
    --device "$IOS_DEVICE" \
    --activate \
    "$bundle" >/dev/null
  sleep 1
}
