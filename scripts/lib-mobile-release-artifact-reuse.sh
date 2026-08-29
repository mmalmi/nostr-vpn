#!/usr/bin/env bash

# Fail-closed validation for reusing the exact mobile Release artifacts built
# and exercised by the physical WireGuard/DNS lanes.

release_join_android_apkanalyzer() {
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
  find "$sdk/cmdline-tools" -type f -name apkanalyzer 2>/dev/null \
    | sort -V \
    | tail -n 1
}

release_join_load_reused_android_artifact_source() {
  local android_source extra
  [[ -s "${NVPN_RELEASE_JOIN_ANDROID_RECEIPT:-}" ]] || {
    echo "Strict Release join artifact reuse requires NVPN_RELEASE_JOIN_ANDROID_RECEIPT" >&2
    return 1
  }
  android_source="$(
    python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" \
      artifact-source \
      --receipt "$NVPN_RELEASE_JOIN_ANDROID_RECEIPT" \
      --artifact-type "Android Release APK"
  )" || return 1
  IFS=$'\t' read -r \
    RELEASE_JOIN_ANDROID_APP_SHA RELEASE_JOIN_ANDROID_APP_TREE extra \
    <<<"$android_source"
  [[ -z "${extra:-}" ]] || return 1
  export RELEASE_JOIN_ANDROID_APP_SHA RELEASE_JOIN_ANDROID_APP_TREE
}

release_join_load_reused_artifact_sources() {
  local ios_source extra
  release_join_load_reused_android_artifact_source || return 1
  for name in \
    NVPN_RELEASE_JOIN_IOS_RECEIPT \
    NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT
  do
    [[ -s "${!name:-}" ]] || {
      echo "Strict Release join artifact reuse requires $name" >&2
      return 1
    }
  done
  ios_source="$(
    python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" \
      artifact-source \
      --receipt "$NVPN_RELEASE_JOIN_IOS_RECEIPT" \
      --artifact-type "iOS Ad Hoc Release join-test variant"
  )" || return 1
  IFS=$'\t' read -r \
    RELEASE_JOIN_IOS_APP_SHA RELEASE_JOIN_IOS_APP_TREE extra \
    <<<"$ios_source"
  [[ -z "${extra:-}" ]] || return 1
  export RELEASE_JOIN_IOS_APP_SHA RELEASE_JOIN_IOS_APP_TREE
}

release_join_validate_android_reuse() {
  local package="${NVPN_DEFAULT_APP_ID:-fi.siriusbusiness.nvpn}"
  local apk="${NVPN_RELEASE_JOIN_ANDROID_APK:-}"
  local receipt="${NVPN_RELEASE_JOIN_ANDROID_RECEIPT:-}"
  local metadata="${NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT:-}"
  local apksigner apkanalyzer cert_sha actual_package app_sha app_tree
  for name in \
    NVPN_RELEASE_JOIN_ANDROID_APK \
    NVPN_RELEASE_JOIN_ANDROID_RECEIPT \
    NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT
  do
    [[ -n "${!name:-}" ]] || {
      echo "Strict Release join artifact reuse requires $name" >&2
      return 1
    }
  done
  [[ -n "${RELEASE_JOIN_ANDROID_APP_SHA:-}" \
    && -n "${RELEASE_JOIN_ANDROID_APP_TREE:-}" ]] \
    || release_join_load_reused_artifact_sources || return 1
  app_sha="$RELEASE_JOIN_ANDROID_APP_SHA"
  app_tree="$RELEASE_JOIN_ANDROID_APP_TREE"
  apksigner="$(release_join_android_apksigner)"
  apkanalyzer="$(release_join_android_apkanalyzer)"
  [[ -x "$apksigner" && -x "$apkanalyzer" ]] || {
    echo "Strict Android Release artifact validation requires apksigner and apkanalyzer" >&2
    return 1
  }
  "$apksigner" verify "$apk" >/dev/null || {
    echo "Reused Android Release APK signature verification failed" >&2
    return 1
  }
  cert_sha="$(
    "$apksigner" verify --print-certs "$apk" 2>/dev/null \
      | awk 'index($0, "certificate SHA-256 digest: ") { sub(/^.*certificate SHA-256 digest: /, ""); print; exit }' \
      | head -n 1 \
      | tr '[:upper:]' '[:lower:]'
  )"
  [[ "$cert_sha" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Reused Android Release APK has no signer certificate digest" >&2
    return 1
  }
  local expected_cert="${NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256:-}"
  expected_cert="$(
    printf '%s' "$expected_cert" \
      | tr -d ':[:space:]' \
      | tr '[:upper:]' '[:lower:]'
  )"
  [[ "$expected_cert" =~ ^[0-9a-f]{64}$ \
    && "$cert_sha" == "$expected_cert" ]] || {
    echo "Reused Android Release APK signer does not match the pinned company key" >&2
    return 1
  }
  actual_package="$("$apkanalyzer" manifest application-id "$apk")"
  if ! python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" \
    validate-android \
    --receipt "$receipt" \
    --apk "$apk" \
    --fips-metadata "$metadata" \
    --app-root "$ROOT" \
    --fips-root "$NVPN_FIPS_REPO_PATH" \
    --app-head "$app_sha" \
    --app-tree "$app_tree" \
    --fips-head "$RELEASE_JOIN_FIPS_SHA" \
    --fips-tree "$RELEASE_JOIN_FIPS_TREE" \
    --fips-version "$RELEASE_JOIN_FIPS_VERSION" \
    --package "$package" \
    --actual-package "$actual_package" \
    --signer-sha "$cert_sha"
  then
    echo "Reused Android Release artifact receipt validation failed" >&2
    return 1
  fi
  RELEASE_JOIN_ANDROID_APK="$apk"
  RELEASE_JOIN_ANDROID_APK_SHA="$(release_join_sha256 "$apk")"
  RELEASE_JOIN_ANDROID_SIGNER_SHA="$cert_sha"
  export RELEASE_JOIN_ANDROID_APK RELEASE_JOIN_ANDROID_APK_SHA
  export RELEASE_JOIN_ANDROID_SIGNER_SHA
}

release_join_codesign_cdhash() {
  codesign -dvvv "$1" 2>&1 \
    | sed -n 's/^CDHash=//p' \
    | head -n 1
}

release_join_validate_ios_reuse() {
  local bundle="${NVPN_DEFAULT_IOS_BUNDLE_ID:-fi.siriusbusiness.nvpn}"
  local tunnel_bundle="$bundle.PacketTunnel"
  local app="${NVPN_RELEASE_JOIN_IOS_APP_PATH:-}"
  local derived="${NVPN_RELEASE_JOIN_IOS_DERIVED_DATA:-}"
  local xctestrun="${NVPN_RELEASE_JOIN_IOS_XCTESTRUN:-}"
  local receipt="${NVPN_RELEASE_JOIN_IOS_RECEIPT:-}"
  local metadata="${NVPN_RELEASE_JOIN_IOS_FIPS_METADATA_RECEIPT:-}"
  local team="${NVPN_IOS_TEAM_ID:-}"
  local expected_team="${NVPN_EXPECTED_IOS_DISTRIBUTION_TEAM_ID:-}"
  local expected_cert="${NVPN_EXPECTED_IOS_DISTRIBUTION_CERT_SHA256:-}"
  local tunnel_app runner test_bundle app_cert tunnel_cert app_cdhash tunnel_cdhash
  local udid device_identifier_sha audit_dir app_profile tunnel_profile
  local app_signed_team tunnel_signed_team runner_signed_team test_signed_team
  local runner_details test_details app_sha app_tree
  for name in \
    NVPN_RELEASE_JOIN_IOS_APP_PATH \
    NVPN_RELEASE_JOIN_IOS_DERIVED_DATA \
    NVPN_RELEASE_JOIN_IOS_XCTESTRUN \
    NVPN_RELEASE_JOIN_IOS_RECEIPT \
    NVPN_RELEASE_JOIN_IOS_FIPS_METADATA_RECEIPT
  do
    [[ -n "${!name:-}" ]] || {
      echo "Strict Release join artifact reuse requires $name" >&2
      return 1
    }
  done
  [[ "$expected_team" =~ ^[A-Z0-9]{10}$ \
    && "$team" == "$expected_team" ]] || {
    echo "Strict iOS Release artifact validation requires the pinned company team" >&2
    return 1
  }
  expected_cert="$(
    printf '%s' "$expected_cert" \
      | tr -d ':[:space:]' \
      | tr '[:upper:]' '[:lower:]'
  )"
  [[ "$expected_cert" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Strict iOS Release artifact validation requires the signer pin" >&2
    return 1
  }
  tunnel_app="$app/PlugIns/Nostr VPN Tunnel.appex"
  runner="$derived/Build/Products/Release-iphoneos/NostrVpnIosUITests-Runner.app"
  test_bundle="$runner/PlugIns/NostrVpnIosUITests.xctest"
  [[ -d "$app" && -d "$tunnel_app" && -d "$derived/Build/Products" \
    && -d "$runner" && -d "$test_bundle" \
    && -s "$xctestrun" && -s "$receipt" && -s "$metadata" ]] || {
    echo "Strict iOS Release artifact set is incomplete" >&2
    return 1
  }
  codesign --verify --deep --strict "$app" >/dev/null 2>&1 \
    && codesign --verify --strict "$tunnel_app" >/dev/null 2>&1 \
    && codesign --verify --deep --strict "$runner" >/dev/null 2>&1 \
    && codesign --verify --strict "$test_bundle" >/dev/null 2>&1 || {
      echo "Reused iOS Release artifact signature verification failed" >&2
      return 1
    }
  app_signed_team="$(release_join_codesign_team "$app")"
  tunnel_signed_team="$(release_join_codesign_team "$tunnel_app")"
  runner_signed_team="$(release_join_codesign_team "$runner")"
  test_signed_team="$(release_join_codesign_team "$test_bundle")"
  [[ "$app_signed_team" == "$expected_team" \
    && "$tunnel_signed_team" == "$expected_team" \
    && "$runner_signed_team" == "$expected_team" \
    && "$test_signed_team" == "$expected_team" ]] || {
    echo "Reused iOS app, tunnel, or runner has the wrong team" >&2
    return 1
  }
  runner_details="$(codesign -dvvv "$runner" 2>&1)"
  test_details="$(codesign -dvvv "$test_bundle" 2>&1)"
  [[ "$runner_details" == *"Authority=Apple Development:"* \
    && "$test_details" == *"Authority=Apple Development:"* ]] || {
    echo "Reused iOS UI runner is not development signed" >&2
    return 1
  }
  app_cert="$(release_join_codesign_certificate_sha256 "$app")"
  tunnel_cert="$(release_join_codesign_certificate_sha256 "$tunnel_app")"
  [[ "$app_cert" == "$expected_cert" && "$tunnel_cert" == "$expected_cert" ]] || {
    echo "Reused iOS Release app or Packet Tunnel has the wrong signer" >&2
    return 1
  }
  app_cdhash="$(release_join_codesign_cdhash "$app")"
  tunnel_cdhash="$(release_join_codesign_cdhash "$tunnel_app")"
  [[ "$app_cdhash" =~ ^[0-9a-fA-F]+$ \
    && "$tunnel_cdhash" =~ ^[0-9a-fA-F]+$ ]] || {
    echo "Reused iOS Release artifact has no CodeDirectory hashes" >&2
    return 1
  }
  udid="$(resolve_physical_ios_udid "$IOS_DEVICE")"
  device_identifier_sha="$(
    printf '%s' "$udid" | shasum -a 256 | awk '{print $1}'
  )"
  audit_dir="$(mktemp -d "$PRIVATE_DIR/ios-reuse-audit.XXXXXX")"
  app_profile="$audit_dir/app-profile.plist"
  tunnel_profile="$audit_dir/tunnel-profile.plist"
  if ! security cms -D -i "$app/embedded.mobileprovision" >"$app_profile" \
    || ! security cms -D -i \
      "$tunnel_app/embedded.mobileprovision" >"$tunnel_profile" \
    || ! python3 - \
      "$app_profile" "$tunnel_profile" "$expected_team" "$expected_cert" \
      "$udid" "$bundle" "$tunnel_bundle" <<'PY'
import hashlib
import plistlib
import sys

app_path, tunnel_path, team, signer, udid, app_bundle, tunnel_bundle = sys.argv[1:]
for path, bundle in ((app_path, app_bundle), (tunnel_path, tunnel_bundle)):
    profile = plistlib.load(open(path, "rb"))
    if udid not in profile.get("ProvisionedDevices", []):
        raise SystemExit("reused Ad Hoc profile does not include the selected phone")
    if profile.get("ProvisionsAllDevices") is True:
        raise SystemExit("reused iOS artifact has an enterprise profile")
    if profile.get("TeamIdentifier") != [team]:
        raise SystemExit("reused iOS profile belongs to the wrong team")
    entitlements = profile.get("Entitlements", {})
    if entitlements.get("get-task-allow") is True:
        raise SystemExit("reused iOS profile is debuggable")
    if entitlements.get("application-identifier") != f"{team}.{bundle}":
        raise SystemExit("reused iOS profile has the wrong application identifier")
    signers = {
        hashlib.sha256(value).hexdigest()
        for value in profile.get("DeveloperCertificates", [])
    }
    if signer not in signers:
        raise SystemExit("reused iOS profile does not authorize the pinned signer")
PY
  then
    rm -rf "$audit_dir"
    echo "Reused iOS Release provisioning-profile validation failed" >&2
    return 1
  fi
  rm -rf "$audit_dir"
  [[ -n "${RELEASE_JOIN_IOS_APP_SHA:-}" \
    && -n "${RELEASE_JOIN_IOS_APP_TREE:-}" ]] \
    || release_join_load_reused_artifact_sources || return 1
  app_sha="$RELEASE_JOIN_IOS_APP_SHA"
  app_tree="$RELEASE_JOIN_IOS_APP_TREE"
  if ! python3 "$ROOT/scripts/mobile_release_artifact_receipt.py" \
    validate-ios \
    --receipt "$receipt" \
    --app "$app" \
    --derived-data "$derived" \
    --xctestrun "$xctestrun" \
    --fips-metadata "$metadata" \
    --fips-root "$NVPN_FIPS_REPO_PATH" \
    --app-head "$app_sha" \
    --app-tree "$app_tree" \
    --fips-head "$RELEASE_JOIN_FIPS_SHA" \
    --fips-tree "$RELEASE_JOIN_FIPS_TREE" \
    --fips-version "$RELEASE_JOIN_FIPS_VERSION" \
    --bundle "$bundle" \
    --signer-sha "$app_cert" \
    --app-cdhash "$app_cdhash" \
    --tunnel-cdhash "$tunnel_cdhash" \
    --device-identifier-sha "$device_identifier_sha" \
    --production-receipt "$NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT"
  then
    echo "Reused iOS Release artifact receipt validation failed" >&2
    return 1
  fi
  RELEASE_JOIN_IOS_DERIVED_DATA="$derived"
  RELEASE_JOIN_IOS_APP_PATH="$app"
  RELEASE_JOIN_IOS_XCTESTRUN="$xctestrun"
  RELEASE_JOIN_IOS_UDID="$udid"
  RELEASE_JOIN_IOS_APP_CERT="$app_cert"
  RELEASE_JOIN_IOS_APP_TREE_SHA="$(
    python3 - "$receipt" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["appBundleTreeSha256"])
PY
  )"
  RELEASE_JOIN_IOS_BUNDLE_MANIFEST_SHA="$(
    release_join_ios_tree_receipt \
      "$app" "$PRIVATE_DIR/ios-reuse-bundle-manifest.json"
  )" || return 1
  export RELEASE_JOIN_IOS_DERIVED_DATA RELEASE_JOIN_IOS_APP_PATH
  export RELEASE_JOIN_IOS_XCTESTRUN RELEASE_JOIN_IOS_UDID
  export RELEASE_JOIN_IOS_APP_CERT RELEASE_JOIN_IOS_APP_TREE_SHA
  export RELEASE_JOIN_IOS_BUNDLE_MANIFEST_SHA
}

release_join_validate_reused_artifacts() {
  release_join_reuse_artifacts || return 0
  release_join_load_reused_artifact_sources || return 1
  release_join_validate_android_reuse || return 1
  release_join_validate_ios_reuse || return 1
  release_join_assert_fips_unchanged || return 1
  [[ -n "${APP_GIT_SHA:-}" && -n "${APP_GIT_TREE:-}" ]] || {
    echo "Release join harness source identity is missing" >&2
    return 1
  }
  release_join_assert_app_unchanged \
    "$APP_GIT_SHA" "$APP_GIT_TREE" || return 1
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  export RELEASE_JOIN_ARTIFACTS_VALIDATED
  echo "Exact Android and iOS Release artifacts validated before device mutation"
}

release_join_validate_reused_android_only() {
  release_join_reuse_artifacts || return 1
  release_join_load_reused_android_artifact_source || return 1
  release_join_validate_android_reuse || return 1
  release_join_assert_fips_unchanged || return 1
  release_join_assert_app_unchanged \
    "$APP_GIT_SHA" "$APP_GIT_TREE" || return 1
  RELEASE_JOIN_ARTIFACTS_VALIDATED=1
  export RELEASE_JOIN_ARTIFACTS_VALIDATED
  echo "Exact Android Release artifact validated before Pixel mutation"
}
