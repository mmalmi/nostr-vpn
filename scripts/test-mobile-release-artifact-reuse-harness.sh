#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT/scripts/mobile_release_artifact_receipt.py"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-artifact-reuse.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

APP_ROOT="$TMP_ROOT/app-checkout"
FIPS_ROOT="$TMP_ROOT/fips-checkout"
ANDROID_DIR="$TMP_ROOT/android"
IOS_DERIVED="$TMP_ROOT/ios-derived"
IOS_PRODUCTS="$IOS_DERIVED/Build/Products"
IOS_APP="$IOS_PRODUCTS/Release-iphoneos/Nostr VPN.app"
IOS_TUNNEL="$IOS_APP/PlugIns/Nostr VPN Tunnel.appex"
IOS_XCTESTRUN="$IOS_PRODUCTS/NostrVpnIos_fixture.xctestrun"
mkdir -p \
  "$APP_ROOT" \
  "$FIPS_ROOT" \
  "$ANDROID_DIR" \
  "$IOS_TUNNEL" \
  "$IOS_PRODUCTS/Release-iphoneos/NostrVpnIosUITests-Runner.app/PlugIns/NostrVpnIosUITests.xctest"

printf 'apk fixture\n' >"$ANDROID_DIR/app-release.apk"
printf 'aab fixture\n' >"$ANDROID_DIR/app-release.aab"
printf 'app executable\n' >"$IOS_APP/Nostr VPN"
printf 'tunnel executable\n' >"$IOS_TUNNEL/Nostr VPN Tunnel"
printf 'app profile\n' >"$IOS_APP/embedded.mobileprovision"
printf 'tunnel profile\n' >"$IOS_TUNNEL/embedded.mobileprovision"
printf 'runner product\n' >"$IOS_PRODUCTS/Release-iphoneos/NostrVpnIosUITests-Runner.app/runner"

ANDROID_APP_HEAD=1111111111111111111111111111111111111111
ANDROID_APP_TREE=2222222222222222222222222222222222222222
IOS_APP_HEAD=5555555555555555555555555555555555555555
IOS_APP_TREE=6666666666666666666666666666666666666666
FIPS_HEAD=3333333333333333333333333333333333333333
FIPS_TREE=4444444444444444444444444444444444444444
FIPS_VERSION=1.2.3
SIGNER_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
APP_CDHASH=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
TUNNEL_CDHASH=cccccccccccccccccccccccccccccccccccccccc
DEVICE_SHA=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
PACKAGE=fi.siriusbusiness.nvpn
ANDROID_METADATA="$ANDROID_DIR/fips-linkage.json"
ANDROID_RECEIPT="$ANDROID_DIR/mobile-android-release-artifact.json"
ANDROID_BUNDLE_RECEIPT="$ANDROID_DIR/physical-gate-artifact.json"
IOS_METADATA="$TMP_ROOT/ios-fips-linkage.json"
IOS_RECEIPT="$TMP_ROOT/mobile-ios-release-artifact.json"
IOS_PRODUCTION_RECEIPT="$TMP_ROOT/mobile-ios-production-artifact.json"

python3 - \
  "$VALIDATOR" "$APP_ROOT" "$FIPS_ROOT" \
  "$ANDROID_DIR/app-release.apk" "$ANDROID_DIR/app-release.aab" \
  "$ANDROID_METADATA" "$ANDROID_RECEIPT" "$ANDROID_BUNDLE_RECEIPT" \
  "$IOS_APP" "$IOS_DERIVED" "$IOS_XCTESTRUN" "$IOS_METADATA" \
  "$IOS_RECEIPT" "$IOS_PRODUCTION_RECEIPT" \
  "$ANDROID_APP_HEAD" "$ANDROID_APP_TREE" \
  "$IOS_APP_HEAD" "$IOS_APP_TREE" \
  "$FIPS_HEAD" "$FIPS_TREE" "$FIPS_VERSION" \
  "$SIGNER_SHA" "$APP_CDHASH" "$TUNNEL_CDHASH" "$DEVICE_SHA" "$PACKAGE" <<'PY'
import importlib.util
import json
import pathlib
import plistlib
import sys

(
    module_path,
    app_root,
    fips_root,
    apk,
    aab,
    android_metadata,
    android_receipt,
    android_bundle_receipt,
    ios_app,
    ios_derived,
    ios_xctestrun,
    ios_metadata,
    ios_receipt,
    ios_production_receipt,
    android_app_head,
    android_app_tree,
    ios_app_head,
    ios_app_tree,
    fips_head,
    fips_tree,
    fips_version,
    signer,
    app_cdhash,
    tunnel_cdhash,
    device_sha,
    package,
) = sys.argv[1:]
spec = importlib.util.spec_from_file_location("artifact_receipt", module_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
app_root = pathlib.Path(app_root)
fips_root = pathlib.Path(fips_root)
apk = pathlib.Path(apk)
aab = pathlib.Path(aab)
android_metadata = pathlib.Path(android_metadata)
android_receipt = pathlib.Path(android_receipt)
android_bundle_receipt = pathlib.Path(android_bundle_receipt)
ios_app = pathlib.Path(ios_app)
ios_derived = pathlib.Path(ios_derived)
ios_xctestrun = pathlib.Path(ios_xctestrun)
ios_metadata = pathlib.Path(ios_metadata)
ios_receipt = pathlib.Path(ios_receipt)
ios_production_receipt = pathlib.Path(ios_production_receipt)

metadata = {
    "checkoutPathSha256": module.path_sha256(fips_root),
    "checkoutHead": fips_head,
    "checkoutTree": fips_tree,
    "fipsCoreVersion": fips_version,
}
android_metadata.write_text(
    json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
)
ios_metadata.write_text(
    json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
)
android = {
    "receiptSchema": 2,
    "artifactType": "Android Release APK",
    "apkPathSha256": module.path_sha256(apk),
    "apkSha256": module.sha256_file(apk),
    "installedApkSha256": module.sha256_file(apk),
    "aabSha256": module.sha256_file(aab),
    "apkDerivedFromAab": True,
    "companySigningVerified": True,
    "signerCertificateSha256": signer,
    "appGitSha": android_app_head,
    "appGitTree": android_app_tree,
    "fipsGitSha": fips_head,
    "fipsGitTree": fips_tree,
    "fipsCoreVersion": fips_version,
    "fipsCheckoutPathSha256": module.path_sha256(fips_root),
    "fipsCargoMetadataReceiptPathSha256": module.path_sha256(android_metadata),
    "fipsCargoMetadataReceiptSha256": module.sha256_file(android_metadata),
    "fipsDependenciesForcedRebuilt": True,
    "package": package,
    "replacementInstall": True,
    "debuggable": False,
}
android_bundle = {
    "schema": 1,
    "relationship": "universal-apk-derived-from-exact-aab",
    "appGitSha": android_app_head,
    "appGitTree": android_app_tree,
    "aabSha256": module.sha256_file(aab),
    "aabPathSha256": module.path_sha256(aab),
    "apkSha256": module.sha256_file(apk),
    "apkPathSha256": module.path_sha256(apk),
    "bundletoolVersion": "1.18.3",
    "bundletoolSha256": "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29",
}
android_bundle_receipt.write_text(
    json.dumps(android_bundle, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
android.update(
    {
        "bundleReceiptSha256": module.sha256_file(android_bundle_receipt),
        "bundletoolVersion": android_bundle["bundletoolVersion"],
        "bundletoolSha256": android_bundle["bundletoolSha256"],
    }
)
android_receipt.write_text(
    json.dumps(android, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
with (ios_app / "Info.plist").open("wb") as handle:
    plistlib.dump(
        {
            "CFBundleDisplayName": "Nostr VPN Test Files",
            "CFBundleIdentifier": package,
            "CFBundleShortVersionString": "4.1.5",
            "CFBundleVersion": "4001007",
            "LSSupportsOpeningDocumentsInPlace": True,
            "UIFileSharingEnabled": True,
        },
        handle,
    )
runner = (
    ios_derived
    / "Build/Products/Release-iphoneos/NostrVpnIosUITests-Runner.app"
)
with (runner / "Info.plist").open("wb") as handle:
    plistlib.dump(
        {"CFBundleIdentifier": f"{package}.UITests.xctrunner"},
        handle,
    )
with ios_xctestrun.open("wb") as handle:
    plistlib.dump(
        {
            "NostrVpnIosUITests": {
                "EnvironmentVariables": {},
                "TestBundlePath": "__TESTHOST__/PlugIns/NostrVpnIosUITests.xctest",
                "TestHostPath": "__TESTROOT__/NostrVpnIosUITests-Runner.app",
                "UITargetAppPath": "__TESTROOT__/Release-iphoneos/Nostr VPN.app",
            }
        },
        handle,
    )
products = ios_derived / "Build" / "Products"
ios = {
    "receiptSchema": 2,
    "artifactType": "iOS company Ad Hoc Release app",
    "appCodeDirectoryHash": app_cdhash,
    "packetTunnelCodeDirectoryHash": tunnel_cdhash,
    "appExecutableSha256": module.sha256_file(ios_app / "Nostr VPN"),
    "packetTunnelExecutableSha256": module.sha256_file(
        ios_app / "PlugIns" / "Nostr VPN Tunnel.appex" / "Nostr VPN Tunnel"
    ),
    "appGitSha": ios_app_head,
    "appGitTree": ios_app_tree,
    "appPathSha256": module.path_sha256(ios_app),
    "appBundleTreeSha256": module.tree_sha256(ios_app),
    "treeSha256": module.tree_sha256(ios_app),
    "derivedDataPathSha256": module.path_sha256(ios_derived),
    "testProductsPathSha256": module.path_sha256(products),
    "testProductsTreeSha256": module.tree_sha256(products),
    "xctestrunPathSha256": module.path_sha256(ios_xctestrun),
    "xctestrunSha256": module.sha256_file(ios_xctestrun),
    "fipsGitSha": fips_head,
    "fipsGitTree": fips_tree,
    "fipsCoreVersion": fips_version,
    "fipsCheckoutPathSha256": module.path_sha256(fips_root),
    "fipsCargoMetadataReceiptPathSha256": module.path_sha256(ios_metadata),
    "fipsCargoMetadataReceiptSha256": module.sha256_file(ios_metadata),
    "fipsDependenciesForcedRebuilt": True,
    "appProvisioningProfileSha256": module.sha256_file(
        ios_app / "embedded.mobileprovision"
    ),
    "packetTunnelProvisioningProfileSha256": module.sha256_file(
        ios_app / "PlugIns" / "Nostr VPN Tunnel.appex" / "embedded.mobileprovision"
    ),
    "companySigningVerified": True,
    "signerCertificateSha256": signer,
    "selectedPhysicalDeviceIdentifierSha256": device_sha,
    "selectedPhysicalDevice": {
        "deviceIdentifierSha256": device_sha,
        "explicitPhysicalDeviceVerified": True,
        "model": "Fixture Phone",
        "platform": "iOS",
        "productType": "Fixture1,1",
    },
    "installedBundleIdentifier": package,
    "cashuAndPaidExitCompiled": False,
    "paidExitWalletWorkerCompiled": False,
    "updaterCompiled": False,
    "debuggable": False,
}
production = {
    **ios,
    "appBundleTreeSha256": "e" * 64,
    "treeSha256": "e" * 64,
    "appExecutableSha256": "f" * 64,
    "appCodeDirectoryHash": "d" * 40,
}
ios_production_receipt.write_text(
    json.dumps(production, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

create_ios_variant() {
  local production_receipt="${1:-$IOS_PRODUCTION_RECEIPT}"
  local output_receipt="${2:-$IOS_RECEIPT}"
  python3 "$VALIDATOR" create-ios-join-variant \
    --receipt "$output_receipt" \
    --production-receipt "$production_receipt" \
    --app "$IOS_APP" \
    --derived-data "$IOS_DERIVED" \
    --xctestrun "$IOS_XCTESTRUN" \
    --app-head "$IOS_APP_HEAD" \
    --app-tree "$IOS_APP_TREE" \
    --fips-head "$FIPS_HEAD" \
    --fips-tree "$FIPS_TREE" \
    --fips-version "$FIPS_VERSION" \
    --bundle "$PACKAGE" \
    --signer-sha "$SIGNER_SHA" \
    --app-cdhash "$APP_CDHASH" \
    --tunnel-cdhash "$TUNNEL_CDHASH" \
    --device-identifier-sha "$DEVICE_SHA"
}

create_ios_variant
python3 - "$IOS_RECEIPT" "$IOS_PRODUCTION_RECEIPT" <<'PY'
import hashlib
import json
import pathlib
import sys

variant_path, production_path = map(pathlib.Path, sys.argv[1:])
variant = json.loads(variant_path.read_text(encoding="utf-8"))
production = json.loads(production_path.read_text(encoding="utf-8"))
assert variant["artifactType"] == "iOS Ad Hoc Release join-test variant"
assert variant["joinTestingCompilationConditionEnabled"] is True
assert variant["fileSharingFixture"] == {
    "bundleIdentifier": variant["installedBundleIdentifier"],
    "displayName": "Nostr VPN Test Files",
    "scope": "join-test-variant-only",
}
assert variant["productionAppByteIdentical"] is False
assert variant["productionArtifactReceiptSha256"] == hashlib.sha256(
    production_path.read_bytes()
).hexdigest()
for field in (
    "appBundleTreeSha256",
    "appExecutableSha256",
    "appCodeDirectoryHash",
):
    assert variant[field] != production[field]
PY

for field in appBundleTreeSha256 appExecutableSha256 appCodeDirectoryHash; do
  collision_receipt="$TMP_ROOT/ios-production-$field.json"
  collision_output="$TMP_ROOT/ios-variant-$field.json"
  python3 - "$IOS_PRODUCTION_RECEIPT" "$IOS_RECEIPT" \
    "$collision_receipt" "$field" <<'PY'
import json
import pathlib
import sys

production_path, variant_path, output_path = map(pathlib.Path, sys.argv[1:4])
field = sys.argv[4]
production = json.loads(production_path.read_text(encoding="utf-8"))
variant = json.loads(variant_path.read_text(encoding="utf-8"))
production[field] = variant[field]
output_path.write_text(json.dumps(production) + "\n", encoding="utf-8")
PY
  if create_ios_variant "$collision_receipt" "$collision_output" \
      >"$TMP_ROOT/ios-variant-$field.log" 2>&1
  then
    echo "iOS join variant accepted production-identical $field" >&2
    exit 1
  fi
done

validate_android() {
  local dir="${1:-$ANDROID_DIR}"
  python3 "$VALIDATOR" validate-android \
    --receipt "$dir/mobile-android-release-artifact.json" \
    --apk "$dir/app-release.apk" \
    --aab "$dir/app-release.aab" \
    --bundle-receipt "$dir/physical-gate-artifact.json" \
    --fips-metadata "$dir/fips-linkage.json" \
    --app-root "$APP_ROOT" \
    --fips-root "$FIPS_ROOT" \
    --app-head "$ANDROID_APP_HEAD" \
    --app-tree "$ANDROID_APP_TREE" \
    --fips-head "$FIPS_HEAD" \
    --fips-tree "$FIPS_TREE" \
    --fips-version "$FIPS_VERSION" \
    --package "$PACKAGE" \
    --actual-package "$PACKAGE" \
    --signer-sha "$SIGNER_SHA"
}

validate_ios() {
  python3 "$VALIDATOR" validate-ios \
    --receipt "$IOS_RECEIPT" \
    --app "$IOS_APP" \
    --derived-data "$IOS_DERIVED" \
    --xctestrun "$IOS_XCTESTRUN" \
    --fips-metadata "$IOS_METADATA" \
    --fips-root "$FIPS_ROOT" \
    --app-head "$IOS_APP_HEAD" \
    --app-tree "$IOS_APP_TREE" \
    --fips-head "$FIPS_HEAD" \
    --fips-tree "$FIPS_TREE" \
    --fips-version "$FIPS_VERSION" \
    --bundle "$PACKAGE" \
    --signer-sha "$SIGNER_SHA" \
    --app-cdhash "$APP_CDHASH" \
    --tunnel-cdhash "$TUNNEL_CDHASH" \
    --device-identifier-sha "$DEVICE_SHA" \
    --production-receipt "$IOS_PRODUCTION_RECEIPT"
}

validate_android
validate_ios

ANDROID_RELOCATED="$TMP_ROOT/relocated/android"
mkdir -p "$ANDROID_RELOCATED"
cp "$ANDROID_DIR"/* "$ANDROID_RELOCATED/"
validate_android "$ANDROID_RELOCATED"
python3 - "$ANDROID_RELOCATED/physical-gate-artifact.json" \
  "$ANDROID_RELOCATED/mobile-android-release-artifact.json" <<'PY'
import hashlib, json, pathlib, sys
bundle_path, receipt_path = map(pathlib.Path, sys.argv[1:])
bundle = json.loads(bundle_path.read_text()); bundle["apkPathSha256"] = "0" * 64
bundle_path.write_text(json.dumps(bundle))
receipt = json.loads(receipt_path.read_text())
receipt["bundleReceiptSha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
receipt_path.write_text(json.dumps(receipt))
PY
if validate_android "$ANDROID_RELOCATED" >/dev/null 2>&1; then
  echo "Android artifact reuse accepted mismatched historical APK binding" >&2
  exit 1
fi

JOIN_TIMINGS="$TMP_ROOT/join-timings.tsv"
JOIN_SUMMARY="$TMP_ROOT/join-summary.json"
ANDROID_QR_CAPTURE="$TMP_ROOT/android-rendered-qr.png"
IOS_QR_CAPTURE="$TMP_ROOT/ios-rendered-qr.png"
printf '\211PNG\r\n\032\n' >"$ANDROID_QR_CAPTURE"
printf '\211PNG\r\n\032\n' >"$IOS_QR_CAPTURE"
printf '%s\t100\n' \
  iPhone-admin-to-Pixel-QR \
  Pixel-admin-to-iPhone-QR \
  iPhone-admin-to-Pixel-manual \
  Pixel-admin-to-iPhone-manual >"$JOIN_TIMINGS"
ANDROID_APK_SHA="$(shasum -a 256 "$ANDROID_DIR/app-release.apk" | awk '{print $1}')"
IOS_BUNDLE_TREE_SHA="$(
  python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["appBundleTreeSha256"])' \
    "$IOS_RECEIPT"
)"
HARNESS_HEAD="$(git -C "$ROOT" rev-parse HEAD)"
HARNESS_TREE="$(git -C "$ROOT" rev-parse HEAD^{tree})"
python3 "$VALIDATOR" join-summary \
  --summary "$JOIN_SUMMARY" \
  --timings "$JOIN_TIMINGS" \
  --harness-head "$HARNESS_HEAD" \
  --harness-tree "$HARNESS_TREE" \
  --android-app-head "$ANDROID_APP_HEAD" \
  --android-app-tree "$ANDROID_APP_TREE" \
  --ios-app-head "$IOS_APP_HEAD" \
  --ios-app-git-tree "$IOS_APP_TREE" \
  --fips-head "$FIPS_HEAD" \
  --fips-tree "$FIPS_TREE" \
  --android-apk-sha "$ANDROID_APK_SHA" \
  --android-receipt "$ANDROID_RECEIPT" \
  --ios-app-bundle-tree-sha "$IOS_BUNDLE_TREE_SHA" \
  --ios-receipt "$IOS_RECEIPT" \
  --ios-production-receipt "$IOS_PRODUCTION_RECEIPT" \
  --android-qr-capture "$ANDROID_QR_CAPTURE" \
  --ios-qr-capture "$IOS_QR_CAPTURE" \
  --android-qr-width-bps 10000 \
  --android-pending-qr-lifecycle-ready 1 \
  --ios-qr-width-bps 10000 \
  --ios-qr-relaunch-durable 1 \
  --ios-admin-manual-relaunch-durable 1 \
  --ios-joiner-manual-relaunch-durable 1
python3 - "$JOIN_SUMMARY" \
  "$HARNESS_HEAD" "$ANDROID_APP_TREE" "$IOS_APP_TREE" \
  "$IOS_BUNDLE_TREE_SHA" <<'PY'
import json
import sys

path, harness_head, android_git_tree, ios_git_tree, ios_bundle_tree = sys.argv[1:]
summary = json.load(open(path, encoding="utf-8"))
assert summary["harnessGitSha"] == harness_head
assert summary["artifact"]["android"]["appGitTree"] == android_git_tree
assert summary["artifact"]["ios"]["appGitTree"] == ios_git_tree
assert summary["artifact"]["ios"]["appBundleTreeSha256"] == ios_bundle_tree
assert summary["productionImageImportQr"] is False
assert summary["iosJoinTestVariant"] is True
assert summary["testOnlyImageImportQr"] is True
assert summary["coverageScope"] == "android-ios-mobile-only"
assert summary["productionQrDecoderPath"] is True
assert summary["productionJoinApprovalPath"] is True
assert summary["productionRosterPath"] is True
assert len(summary["artifact"]["ios"]["appGitTree"]) == 40
assert len(summary["artifact"]["ios"]["appBundleTreeSha256"]) == 64
PY

(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-artifact-reuse.sh"
  NVPN_RELEASE_JOIN_ANDROID_RECEIPT="$ANDROID_RECEIPT"
  unset NVPN_RELEASE_JOIN_IOS_RECEIPT NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT
  release_join_load_reused_android_artifact_source
  [[ "$RELEASE_JOIN_ANDROID_APP_SHA" == "$ANDROID_APP_HEAD" ]]
  [[ "$RELEASE_JOIN_ANDROID_APP_TREE" == "$ANDROID_APP_TREE" ]]
)

(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-artifact-reuse.sh"
  NVPN_RELEASE_JOIN_ANDROID_RECEIPT="$ANDROID_RECEIPT"
  NVPN_RELEASE_JOIN_IOS_RECEIPT="$IOS_RECEIPT"
  NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT="$IOS_PRODUCTION_RECEIPT"
  NVPN_EXPECTED_APP_GIT_SHA="$IOS_APP_HEAD"
  release_join_load_reused_artifact_sources
  [[ "$RELEASE_JOIN_ANDROID_APP_SHA" == "$ANDROID_APP_HEAD" ]]
  [[ "$RELEASE_JOIN_ANDROID_APP_TREE" == "$ANDROID_APP_TREE" ]]
  [[ "$RELEASE_JOIN_IOS_APP_SHA" == "$IOS_APP_HEAD" ]]
  [[ "$RELEASE_JOIN_IOS_APP_TREE" == "$IOS_APP_TREE" ]]
  [[ "$RELEASE_JOIN_ANDROID_APP_SHA" != "$RELEASE_JOIN_IOS_APP_SHA" ]]
  [[ "$RELEASE_JOIN_ANDROID_APP_SHA" != "$NVPN_EXPECTED_APP_GIT_SHA" && "$RELEASE_JOIN_IOS_APP_SHA" == "$NVPN_EXPECTED_APP_GIT_SHA" ]]
  [[ "$RELEASE_JOIN_ANDROID_APP_SHA" != "$(git -C "$ROOT" rev-parse HEAD)" ]]
  [[ "$RELEASE_JOIN_IOS_APP_SHA" != "$(git -C "$ROOT" rev-parse HEAD)" ]]
)

reject_android_file_tamper() {
  local path="$1" label="$2" backup
  backup="$TMP_ROOT/android-$label.clean"
  cp "$path" "$backup"
  printf 'tamper\n' >>"$path"
  if validate_android >"$TMP_ROOT/android-$label-tamper.log" 2>&1; then
    echo "Android artifact receipt accepted tampered $label bytes" >&2
    exit 1
  fi
  mv "$backup" "$path"
}
reject_android_file_tamper "$ANDROID_DIR/app-release.apk" apk
reject_android_file_tamper "$ANDROID_DIR/app-release.aab" aab
reject_android_file_tamper "$ANDROID_BUNDLE_RECEIPT" relationship-receipt

mv "$ANDROID_RECEIPT" "$TMP_ROOT/android-receipt.missing.json"
if validate_android >"$TMP_ROOT/android-receipt-missing.log" 2>&1; then
  echo "Android artifact reuse accepted a missing schema-2 receipt" >&2
  exit 1
fi
mv "$TMP_ROOT/android-receipt.missing.json" "$ANDROID_RECEIPT"

reject_android_receipt_field() {
  local field="$1" value="$2" label="$3"
  cp "$ANDROID_RECEIPT" "$TMP_ROOT/android-receipt.clean.json"
  python3 -c \
    'import json,sys; p,f,v=sys.argv[1:]; r=json.load(open(p)); r[f]=v; json.dump(r,open(p,"w"))' \
    "$ANDROID_RECEIPT" "$field" "$value"
  if validate_android >"$TMP_ROOT/android-$label.log" 2>&1; then
    echo "Android artifact receipt accepted tampered $field" >&2
    exit 1
  fi
  mv "$TMP_ROOT/android-receipt.clean.json" "$ANDROID_RECEIPT"
}

reject_android_receipt_field installedApkSha256 "$(printf '0%.0s' {1..64})" installed-hash
reject_android_receipt_field signerCertificateSha256 "$(printf '0%.0s' {1..64})" signer
reject_android_receipt_field fipsGitSha "$(printf '0%.0s' {1..40})" fips
reject_android_receipt_field bundletoolVersion 0.0.0 bundletool

cp "$ANDROID_RECEIPT" "$TMP_ROOT/android-receipt.clean.json"
python3 - "$ANDROID_RECEIPT" <<'PY'
import json
import sys
path = sys.argv[1]
receipt = json.load(open(path, encoding="utf-8"))
receipt["appGitTree"] = "0" * 40
with open(path, "w", encoding="utf-8") as handle:
    json.dump(receipt, handle)
PY
if validate_android >"$TMP_ROOT/android-tree-mismatch.log" 2>&1; then
  echo "Android artifact receipt accepted a mismatched application tree" >&2
  exit 1
fi
mv "$TMP_ROOT/android-receipt.clean.json" "$ANDROID_RECEIPT"

# The opt-in is rejected before any build/install path or device lookup.
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-android-release-gate.sh"
assert_reuse_input_rejected() {
  local label="$1" expected="$2" log
  log="$TMP_ROOT/android-$label.log"
  if android_release_require_inputs >"$log" 2>&1; then
    echo "Android artifact reuse accepted $label" >&2
    exit 1
  fi
  grep -Fq "$expected" "$log"
}
export NVPN_ANDROID_RELEASE_REUSE_VERIFIED_ARTIFACT=1
PACKAGE_NAME="$PACKAGE"
CANONICAL_PACKAGE_NAME="$PACKAGE"
build=1 install=0
assert_reuse_input_rejected build 'requires --no-build and --no-install'
build=0 install=1
assert_reuse_input_rejected install 'requires --no-build and --no-install'
build=0 install=0
NVPN_MOBILE_ANDROID_RELEASE_RECEIPT="$TMP_ROOT/missing.json"
NVPN_ANDROID_RELEASE_REUSE_AAB_PATH="$ANDROID_DIR/app-release.aab"
NVPN_ANDROID_RELEASE_REUSE_BUNDLE_RECEIPT="$ANDROID_BUNDLE_RECEIPT"
assert_reuse_input_rejected missing-receipt \
  'requires regular file ANDROID_RELEASE_REUSE_RECEIPT'

cp "$IOS_XCTESTRUN" "$TMP_ROOT/ios-xctestrun.clean"
printf 'tamper\n' >>"$IOS_XCTESTRUN"
if validate_ios >"$TMP_ROOT/ios-xctestrun-tamper.log" 2>&1; then
  echo "iOS artifact receipt accepted tampered xctestrun bytes" >&2
  exit 1
fi
mv "$TMP_ROOT/ios-xctestrun.clean" "$IOS_XCTESTRUN"

cp "$IOS_PRODUCTS/Release-iphoneos/NostrVpnIosUITests-Runner.app/runner" "$TMP_ROOT/runner.clean"
printf 'tamper\n' >>"$IOS_PRODUCTS/Release-iphoneos/NostrVpnIosUITests-Runner.app/runner"
if validate_ios >"$TMP_ROOT/ios-products-tamper.log" 2>&1; then
  echo "iOS artifact receipt accepted tampered UI test products" >&2
  exit 1
fi
mv "$TMP_ROOT/runner.clean" "$IOS_PRODUCTS/Release-iphoneos/NostrVpnIosUITests-Runner.app/runner"

ln -s "$TMP_ROOT" "$IOS_PRODUCTS/escaping-product"
if python3 "$VALIDATOR" tree-sha "$IOS_PRODUCTS" \
    >"$TMP_ROOT/ios-symlink-escape.log" 2>&1
then
  echo "iOS artifact tree accepted an escaping test-product symlink" >&2
  exit 1
fi
rm "$IOS_PRODUCTS/escaping-product"

(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-artifact-reuse.sh"
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib-mobile-release-join-ui.sh"
  export NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1
  NVPN_IOS_TEAM_ID=ABCDE12345
  NVPN_DEFAULT_IOS_BUNDLE_ID="$PACKAGE"
  PRIVATE_DIR="$TMP_ROOT/join-private"
  RELEASE_JOIN_IOS_DERIVED_DATA="$IOS_DERIVED"
  RELEASE_JOIN_IOS_APP_PATH="$IOS_APP"
  RELEASE_JOIN_IOS_XCTESTRUN="$IOS_XCTESTRUN"
  RELEASE_JOIN_IOS_UDID=fixture-device
  RELEASE_JOIN_DELIVERY_WAIT_SECS=15
  RELEASE_JOIN_IMPORT_WAIT_SECS=15
  RELEASE_JOIN_IOS_SETUP_WAIT_SECS=30
  mkdir -p "$PRIVATE_DIR"
  base_sha="$(shasum -a 256 "$IOS_XCTESTRUN" | awk '{print $1}')"
  command_file="$TMP_ROOT/join-command.bin"
  release_join_ios_test_command \
    testManualJoinAndRequireRosterCompletion \
    "NVPN_RELEASE_JOIN_ADMIN_ID=npub1fixture" \
    "NVPN_RELEASE_JOIN_NETWORK_ID=fixture-network" \
    >"$command_file"
  python3 - "$command_file" "$IOS_XCTESTRUN" "$base_sha" <<'PY'
import hashlib
import pathlib
import plistlib
import sys

command_path, base_path, base_sha = sys.argv[1:]
command = pathlib.Path(command_path).read_bytes().split(b"\0")
command = [value.decode() for value in command if value]
if "-xctestrun" not in command or "test-without-building" not in command:
    raise SystemExit("strict join command does not use xctestrun test-without-building")
if "-project" in command or "build-for-testing" in command:
    raise SystemExit("strict join command retained a rebuild path")
if "-quiet" in command:
    raise SystemExit("strict join command suppresses XCTest and release markers")
if (
    "-parallel-testing-enabled" not in command
    or command[command.index("-parallel-testing-enabled") + 1] != "NO"
):
    raise SystemExit("strict join command does not serialize the physical runner")
case_path = pathlib.Path(command[command.index("-xctestrun") + 1])
payload = plistlib.load(case_path.open("rb"))["NostrVpnIosUITests"]
environment = payload["EnvironmentVariables"]
expected = {
    "NVPN_RELEASE_JOIN_BLACKBOX": "1",
    "NVPN_RELEASE_JOIN_ADMIN_ID": "npub1fixture",
    "NVPN_RELEASE_JOIN_NETWORK_ID": "fixture-network",
}
for name, value in expected.items():
    if environment.get(name) != value:
        raise SystemExit(f"strict join xctestrun omitted {name}")
actual_base_sha = hashlib.sha256(pathlib.Path(base_path).read_bytes()).hexdigest()
if actual_base_sha != base_sha:
    raise SystemExit("strict join mutated the byte-validated base xctestrun")
PY
)

python3 - \
  "$ROOT/scripts/mobile-release-join-e2e.sh" \
  "$ROOT/scripts/lib-mobile-release-join-artifacts.sh" \
  "$ROOT/scripts/lib-mobile-release-artifact-reuse.sh" \
  "$ROOT/scripts/lib-mobile-release-join-ui.sh" \
  "$ROOT/scripts/release-gate.sh" \
  "$ROOT/scripts/lib-mobile-android-release-gate.sh" \
  "$ROOT/scripts/mobile-android-smoke.sh" <<'PY'
import pathlib
import sys

gate, artifacts, reuse, ui, release, android_release, android_smoke = [
    pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
]
for required in ("HARNESS_GIT_SHA", 'APP_GIT_SHA="${NVPN_EXPECTED_APP_GIT_SHA:-}"', 'APP_GIT_SHA="$HARNESS_GIT_SHA"', "release_join_validate_android_reuse", "release_join_validate_ios_reuse", '--harness-head "$HARNESS_GIT_SHA"'):
    if required not in gate:
        raise SystemExit(f"Release join reuse identity separation is missing {required}")
if '== "$APP_GIT_SHA:$APP_GIT_TREE"' in gate:
    raise SystemExit("Release join falsely requires retained Android identity to equal iOS product")
validation = gate.index("release_join_validate_reused_artifacts")
checkout_rebind = gate.index('APP_GIT_SHA="$HARNESS_GIT_SHA"', validation)
arm = gate.index("RELEASE_JOIN_DEVICE_MUTATION_ALLOWED=1")
android_install = gate.index("release_join_prepare_android_release", validation)
ios_install = gate.index("release_join_prepare_ios_release", validation)
if not validation < checkout_rebind < arm < android_install < ios_install:
    raise SystemExit("Release join does not validate both artifacts before mutation")
if '[[ "${RELEASE_JOIN_DEVICE_MUTATED:-0}" -eq 1 ]]' not in gate:
    raise SystemExit("prevalidation failure can still mutate devices during cleanup")
for required in (
    "NVPN_RELEASE_JOIN_REUSE_ARTIFACTS=1",
    "NVPN_RELEASE_JOIN_ANDROID_APK=",
    "NVPN_RELEASE_JOIN_ANDROID_RECEIPT=",
    "NVPN_RELEASE_JOIN_ANDROID_FIPS_METADATA_RECEIPT=",
    "NVPN_RELEASE_JOIN_IOS_APP_PATH=",
    "NVPN_RELEASE_JOIN_IOS_DERIVED_DATA=",
    "NVPN_RELEASE_JOIN_IOS_XCTESTRUN=",
    "NVPN_RELEASE_JOIN_IOS_RECEIPT=",
    "NVPN_RELEASE_JOIN_IOS_PRODUCTION_RECEIPT=",
    "NVPN_RELEASE_JOIN_IOS_FIPS_METADATA_RECEIPT=",
):
    if required not in release:
        raise SystemExit(f"release gate does not wire strict artifact reuse: {required}")
for required in (
    'export NVPN_MOBILE_ANDROID_RELEASE_RECEIPT="$mobile_artifact_receipt_dir/android.json"',
    'export NVPN_MOBILE_IOS_RELEASE_RECEIPT="$mobile_artifact_receipt_dir/ios.json"',
    'rm -f \\\n    "$NVPN_MOBILE_ANDROID_RELEASE_RECEIPT"',
):
    if required not in release:
        raise SystemExit("release gate can reuse a stale prior-run receipt")
strict_android = artifacts.split(
    "if release_join_reuse_artifacts; then", 1
)[1].split("else", 1)[0]
for forbidden in ("run-android", "build-for-testing"):
    if forbidden in strict_android:
        raise SystemExit(f"strict Android reuse can rebuild through {forbidden}")
if "-xctestrun \"$case_xctestrun\"" not in ui:
    raise SystemExit("strict iOS join does not use its byte-validated xctestrun")
if "test-without-building" not in ui:
    raise SystemExit("strict iOS join no longer uses test-without-building")
for required in (
    "validate-android",
    "validate-ios",
    "release_join_validate_android_reuse",
    "release_join_validate_ios_reuse",
    "release_join_load_reused_artifact_sources",
    "selected phone",
):
    if required not in reuse:
        raise SystemExit(f"strict artifact validator is missing {required}")
reuse_identity = android_release.split(
    "android_release_require_reuse_inputs()", 1
)[1].split("android_release_require_inputs()", 1)[0]
if 'git -C "$ROOT" rev-parse' in reuse_identity:
    raise SystemExit("Android sealed-artifact reuse binds the current checkout")
for required in (
    "RELEASE_JOIN_ANDROID_APP_SHA",
    "RELEASE_JOIN_ANDROID_APP_TREE",
    "RELEASE_JOIN_IOS_APP_SHA",
    "RELEASE_JOIN_IOS_APP_TREE",
):
    if required not in reuse or required not in gate:
        raise SystemExit(f"mixed-source join contract omits {required}")
reuse_branch = android_release.split(
    "if android_release_reuse_verified_artifact; then", 2
)[2]
if reuse_branch.index("return 0") > reuse_branch.index("json.dump("):
    raise SystemExit("Android sealed-artifact reuse reaches the receipt writer")
require = android_smoke.index(
    "android_release_require_inputs", android_smoke.index('ADB="$(resolve_adb)"')
)
build = android_smoke.index('if [[ "$build" -eq 1 ]]', require)
if require > build:
    raise SystemExit("Android sealed-artifact guard runs after the build path")
PY

echo "mobile Release exact-artifact reuse/tamper harness passed"
