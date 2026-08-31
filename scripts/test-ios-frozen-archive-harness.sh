#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/scripts/ios_frozen_archive.py"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-ios-frozen-archive.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

PRODUCTS="$TMP_ROOT/DerivedData/Build/Products"
APP="$TMP_ROOT/frozen/Payload/Nostr VPN.app"
RUNNER="$PRODUCTS/Release-iphoneos/NostrVpnIosUITests-Runner.app"
TEST_BUNDLE="$RUNNER/PlugIns/NostrVpnIosUITests.xctest"
TUNNEL="$APP/PlugIns/Nostr VPN Tunnel.appex"
SOURCE="$PRODUCTS/NostrVpnIos_fixture.xctestrun"
PRIVATE_DIR="$TMP_ROOT/private"
OUTPUT="$PRIVATE_DIR/network-case.xctestrun"
DESTINATION_OUTPUT="$PRIVATE_DIR/network-case-installed.xctestrun"
mkdir -p "$TEST_BUNDLE" "$TUNNEL" "$PRIVATE_DIR"
chmod 700 "$PRIVATE_DIR"
printf 'app\n' >"$APP/Nostr VPN"
printf 'tunnel\n' >"$TUNNEL/Nostr VPN Tunnel"
printf 'test bundle\n' >"$TEST_BUNDLE/NostrVpnIosUITests"

PYTHONPATH="$ROOT/scripts" python3 - "$TMP_ROOT" <<'PY'
import pathlib
import plistlib
import shutil
import sys

from ios_frozen_archive import unsigned_content_manifest

root = pathlib.Path(sys.argv[1])
archive = root / "plist-archive" / "Nostr VPN.app"
export = root / "plist-export" / "Nostr VPN.app"
tunnel = pathlib.Path("PlugIns") / "Nostr VPN Tunnel.appex"
for app in (archive, export):
    (app / tunnel).mkdir(parents=True)
    (app / "asset.bin").write_bytes(b"exact non-plist bytes\n")
values = {
    "CFBundleIdentifier": "example.nvpn",
    "Nested": {"Enabled": True, "Values": [1, 2, 3]},
}
for relative in (pathlib.Path("Info.plist"), tunnel / "Info.plist"):
    with (archive / relative).open("wb") as handle:
        plistlib.dump(values, handle, fmt=plistlib.FMT_XML, sort_keys=False)
    with (export / relative).open("wb") as handle:
        plistlib.dump(values, handle, fmt=plistlib.FMT_BINARY, sort_keys=True)
assert unsigned_content_manifest(archive) != unsigned_content_manifest(export)
assert unsigned_content_manifest(
    archive, canonicalize_plists=True
) == unsigned_content_manifest(export, canonicalize_plists=True)
with (export / tunnel / "Info.plist").open("wb") as handle:
    plistlib.dump({**values, "Nested": {"Enabled": False}}, handle)
assert unsigned_content_manifest(
    archive, canonicalize_plists=True
) != unsigned_content_manifest(export, canonicalize_plists=True)
shutil.copy2(archive / tunnel / "Info.plist", export / tunnel / "Info.plist")
(export / "asset.bin").write_bytes(b"changed non-plist bytes\n")
assert unsigned_content_manifest(
    archive, canonicalize_plists=True
) != unsigned_content_manifest(export, canonicalize_plists=True)
PY

python3 - "$SOURCE" "$APP" "$RUNNER" <<'PY'
import pathlib
import plistlib
import sys

path, app, runner = map(pathlib.Path, sys.argv[1:])
for bundle, identifier in (
    (app, "example.nvpn"),
    (runner, "example.nvpn.UITests.xctrunner"),
):
    with (bundle / "Info.plist").open("wb") as handle:
        plistlib.dump({"CFBundleIdentifier": identifier}, handle)
payload = {
    "CodeCoverageBuildableInfos": [
        {
            "Name": "Nostr VPN.app",
            "ProductPaths": [
                "__TESTROOT__/Release-iphoneos/Nostr VPN.app/Nostr VPN"
            ],
        },
        {
            "Name": "Nostr VPN Tunnel.appex",
            "ProductPaths": [
                "__TESTROOT__/Release-iphoneos/Nostr VPN Tunnel.appex/Nostr VPN Tunnel"
            ],
        },
        {
            "Name": "NostrVpnIosUITests.xctest",
            "ProductPaths": [
                "__TESTROOT__/Release-iphoneos/NostrVpnIosUITests-Runner.app/PlugIns/NostrVpnIosUITests.xctest/NostrVpnIosUITests"
            ],
        },
    ],
    "TestConfigurations": [
        {
            "Name": "Test Scheme Action",
            "TestTargets": [
                {
                    "BlueprintName": "NostrVpnIosUITests",
                    "ClangProfileDataDirectoryPath": "__DERIVEDDATA__/Build/ProfileData/fixture-run",
                    "DependentProductPaths": [
                        "__TESTROOT__/Release-iphoneos/Nostr VPN.app",
                        "__TESTHOST__/PlugIns/NostrVpnIosUITests.xctest",
                    ],
                    "EnvironmentVariables": {
                        "NVPN_RELEASE_JOIN_NETWORK_ID": "stale-private-value",
                    },
                    "ProductModuleName": "NostrVpnIosUITests",
                    "TestBundlePath": "__TESTHOST__/PlugIns/NostrVpnIosUITests.xctest",
                    "TestHostPath": "__TESTROOT__/Release-iphoneos/NostrVpnIosUITests-Runner.app",
                    "TestingEnvironmentVariables": {
                        "DYLD_FRAMEWORK_PATH": "__TESTROOT__/Release-iphoneos",
                        "DYLD_INSERT_LIBRARIES": "__TESTHOST__/Frameworks/TestSupport.dylib",
                        "PROFILE_ROOT": "__DERIVEDDATA__/Build/ProfileData",
                    },
                    "UITargetAppCommandLineArguments": [
                        "--test-only-launch-payload",
                    ],
                    "UITargetAppEnvironmentVariables": {
                        "NVPN_TEST_ONLY_APP_PAYLOAD": "must-not-survive",
                    },
                    "UITargetAppPath": "__TESTROOT__/Release-iphoneos/Nostr VPN.app",
                }
            ],
        }
    ],
}
with path.open("wb") as handle:
    plistlib.dump(payload, handle)
PY

printf '%s\0' \
  NVPN_RELEASE_JOIN_NETWORK_ID= \
  NVPN_RELEASE_JOIN_NETWORK_ID=fixture-network \
  NVPN_RELEASE_JOIN_BLACKBOX=1 \
  | python3 "$TOOL" rewrite-xctestrun \
    --source "$SOURCE" \
    --output "$OUTPUT" \
    --products-root "$PRODUCTS" \
    --target-app "$APP" \
    --environment-stdin0

python3 "$TOOL" rewrite-xctestrun \
  --source "$SOURCE" \
  --output "$DESTINATION_OUTPUT" \
  --products-root "$PRODUCTS" \
  --target-app "$APP" \
  --use-destination-artifacts

python3 - "$DESTINATION_OUTPUT" <<'PY'
import pathlib
import plistlib
import sys

payload = plistlib.load(pathlib.Path(sys.argv[1]).open("rb"))
target = payload["TestConfigurations"][0]["TestTargets"][0]
expected = {
    "UseDestinationArtifacts": True,
    "TestHostBundleIdentifier": "example.nvpn.UITests.xctrunner",
    "TestBundleDestinationRelativePath": "PlugIns/NostrVpnIosUITests.xctest",
    "UITargetAppBundleIdentifier": "example.nvpn",
}
for key, value in expected.items():
    if target.get(key) != value:
        raise SystemExit(f"destination-artifact plan has the wrong {key}")
if target.get("UITargetAppCommandLineArguments") != []:
    raise SystemExit("ordinary destination-artifact plan exposed test-only UI")
for key in (
    "TestBundlePath",
    "TestHostPath",
    "UITargetAppPath",
    "DependentProductPaths",
):
    if key in target:
        raise SystemExit(f"destination-artifact plan retains {key}")
PY

python3 - \
  "$ROOT/scripts/mobile_release_artifact_receipt.py" \
  "$SOURCE" "$OUTPUT" "$APP" "$RUNNER" "$TEST_BUNDLE" "$TUNNEL" <<'PY'
import importlib.util
import pathlib
import plistlib
import stat
import sys

validator_path = sys.argv[1]
source, output, app, runner, test_bundle, tunnel = map(
    pathlib.Path, sys.argv[2:]
)
spec = importlib.util.spec_from_file_location("artifact_receipt", validator_path)
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)
validator.validate_xctestrun(source)
validator.validate_xctestrun(output)
source_payload = plistlib.load(source.open("rb"))
source_target = source_payload["TestConfigurations"][0]["TestTargets"][0]
if "__TESTROOT__" not in source_target["TestHostPath"]:
    raise SystemExit("xctestrun rewrite mutated its immutable source")
payload = plistlib.load(output.open("rb"))
target = payload["TestConfigurations"][0]["TestTargets"][0]
expected = {
    "TestBundlePath": str(test_bundle.resolve()),
    "TestHostPath": str(runner.resolve()),
    "UITargetAppPath": str(app.resolve()),
}
for key, value in expected.items():
    if target.get(key) != value:
        raise SystemExit(f"rewritten xctestrun has the wrong {key}")
dependent = target.get("DependentProductPaths")
if dependent != [
    str(tunnel.resolve()),
    str(app.resolve()),
    str(runner.resolve()),
    str(test_bundle.resolve()),
]:
    raise SystemExit("rewritten xctestrun has the wrong dependent products")
for value in [*expected.values(), *dependent]:
    if not value.startswith("/") or "__TEST" in value:
        raise SystemExit("rewritten xctestrun retained a relocatable path")
environment = target.get("EnvironmentVariables", {})
if environment.get("NVPN_RELEASE_JOIN_NETWORK_ID") != "fixture-network":
    raise SystemExit("xctestrun environment was not scrubbed then replaced")
if environment.get("NVPN_RELEASE_JOIN_BLACKBOX") != "1":
    raise SystemExit("xctestrun runner environment is incomplete")
if target.get("UITargetAppCommandLineArguments") != []:
    raise SystemExit("xctestrun retained app launch arguments")
if target.get("UITargetAppEnvironmentVariables") != {}:
    raise SystemExit("xctestrun retained app launch environment")
for item in payload["CodeCoverageBuildableInfos"]:
    for path in item["ProductPaths"]:
        if not path.startswith("/") or "__TEST" in path:
            raise SystemExit("rewritten xctestrun retained a coverage placeholder")
expected_profile_root = str((runner.parents[2] / "ProfileData").resolve())
expected_clang_profile = str(
    (runner.parents[2] / "ProfileData" / "fixture-run").resolve()
)
if target["ClangProfileDataDirectoryPath"] != expected_clang_profile:
    raise SystemExit("rewritten xctestrun retained __DERIVEDDATA__")
testing_environment = target["TestingEnvironmentVariables"]
if testing_environment["DYLD_FRAMEWORK_PATH"] != str(
    runner.parent.resolve()
):
    raise SystemExit("rewritten xctestrun retained temp-root framework paths")
if testing_environment["DYLD_INSERT_LIBRARIES"] != str(
    (runner / "Frameworks" / "TestSupport.dylib").resolve()
):
    raise SystemExit("rewritten xctestrun retained temp-host library paths")
if testing_environment["PROFILE_ROOT"] != expected_profile_root:
    raise SystemExit("rewritten xctestrun retained derived-data paths")
if stat.S_IMODE(output.stat().st_mode) != 0o600:
    raise SystemExit("private xctestrun is not mode 0600")
PY

if python3 "$TOOL" rewrite-xctestrun \
  --source "$SOURCE" \
  --output "$PRIVATE_DIR/invalid.xctestrun" \
  --products-root "$PRODUCTS" \
  --target-app "$APP" \
  --environment invalid-name=value >/dev/null 2>&1
then
  echo "Frozen iOS helper accepted an invalid runner variable" >&2
  exit 1
fi

DESTINATION_DIR="$TMP_ROOT/destination-products"
mkdir -p "$DESTINATION_DIR"
python3 - "$SOURCE" "$DESTINATION_DIR" <<'PY'
import pathlib
import plistlib
import sys

source, output_dir = map(pathlib.Path, sys.argv[1:])
for name, value in (
    ("boolean", True),
    ("integer", 1),
    ("string", "true"),
):
    payload = plistlib.load(source.open("rb"))
    payload["TestConfigurations"][0]["TestTargets"][0][
        "UseDestinationArtifacts"
    ] = value
    with (output_dir / f"{name}.xctestrun").open("wb") as handle:
        plistlib.dump(payload, handle)
PY
for destination_source in "$DESTINATION_DIR"/*.xctestrun; do
  if python3 "$TOOL" rewrite-xctestrun \
    --source "$destination_source" \
    --output "$PRIVATE_DIR/destination-products-output.xctestrun" \
    --products-root "$PRODUCTS" \
    --target-app "$APP" >/dev/null 2>&1
  then
    echo "Frozen iOS helper accepted destination-side test products" >&2
    exit 1
  fi
done

ARCHIVE_RECEIPT="$TMP_ROOT/archive.json"
ADHOC_RECEIPT="$TMP_ROOT/adhoc.json"
MOBILE_RECEIPT="$TMP_ROOT/mobile.json"
JOIN_VARIANT_RECEIPT="$TMP_ROOT/ios-join-test-variant.json"
MOBILE_JOIN_RECEIPT="$TMP_ROOT/mobile-join.json"
MOBILE_WG_RECEIPT="$TMP_ROOT/mobile-wg.json"
MOBILE_UNDERLAY_RECEIPT="$TMP_ROOT/mobile-underlay.json"
DESKTOP_MOBILE_JOIN_RECEIPT="$TMP_ROOT/desktop-mobile-join.json"
SEALED_MOBILE_RECEIPT="$TMP_ROOT/sealed-mobile.json"
GATE_SEAL="$TMP_ROOT/gate-seal.json"
ARCHIVE_CLEAN="$TMP_ROOT/archive-clean.json"
ADHOC_CLEAN="$TMP_ROOT/adhoc-clean.json"
MOBILE_CLEAN="$TMP_ROOT/mobile-clean.json"
JOIN_VARIANT_CLEAN="$TMP_ROOT/ios-join-test-variant-clean.json"
MOBILE_JOIN_CLEAN="$TMP_ROOT/mobile-join-clean.json"
DESKTOP_MOBILE_JOIN_CLEAN="$TMP_ROOT/desktop-mobile-join-clean.json"

python3 - \
  "$ARCHIVE_RECEIPT" "$ADHOC_RECEIPT" "$MOBILE_RECEIPT" \
  "$JOIN_VARIANT_RECEIPT" \
  "$MOBILE_JOIN_RECEIPT" "$MOBILE_WG_RECEIPT" \
  "$MOBILE_UNDERLAY_RECEIPT" "$DESKTOP_MOBILE_JOIN_RECEIPT" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    archive_path,
    adhoc_path,
    mobile_path,
    variant_path,
    join_path,
    wg_path,
    underlay_path,
    desktop_join_path,
) = map(
    pathlib.Path, sys.argv[1:]
)
identity = {
    "appBundleIdentifier": "example.nvpn",
    "buildNumber": "4001005",
    "marketingVersion": "4.1.5",
}
signing = {
    "appCodeDirectoryHash": "a" * 40,
    "appProvisioningProfileSha256": "b" * 64,
    "packetTunnelCodeDirectoryHash": "c" * 40,
    "packetTunnelProvisioningProfileSha256": "d" * 64,
    "signerCertificateSha256": "e" * 64,
    "signingTeamIdentifier": "AAAAAAAAAA",
}
archive = {
    "receiptSchema": 1,
    "artifactType": "iOS frozen App Store xcarchive",
    "appGitSha": "1" * 40,
    "appGitTree": "2" * 40,
    "archiveAppBundleTreeSha256": "b" * 64,
    "archivePathSha256": "c" * 64,
    "archiveTreeSha256": "3" * 64,
    "fipsCoreVersion": "1.2.3",
    "fipsCargoMetadataReceiptPathSha256": "8" * 64,
    "fipsCargoMetadataReceiptSha256": "9" * 64,
    "fipsCheckoutPathSha256": "a" * 64,
    "fipsGitSha": "4" * 40,
    "fipsGitTree": "5" * 40,
    "identity": identity,
    "rustBuildProfile": "release",
}
adhoc = {
    "receiptSchema": 1,
    "artifactType": "iOS export from frozen xcarchive",
    "appBundleTreeSha256": "6" * 64,
    "appGitSha": archive["appGitSha"],
    "appGitTree": archive["appGitTree"],
    "archiveReceiptSha256": "",
    "archiveTreeSha256": archive["archiveTreeSha256"],
    "distribution": "release-testing",
    "fipsCoreVersion": archive["fipsCoreVersion"],
    "fipsGitSha": archive["fipsGitSha"],
    "fipsGitTree": archive["fipsGitTree"],
    "identity": identity,
    "ipaPathSha256": "d" * 64,
    "ipaSha256": "e" * 64,
    "rustBuildProfile": archive["rustBuildProfile"],
    "signing": signing,
}
mobile = {
    "receiptSchema": 2,
    "artifactType": "iOS company Ad Hoc Release app",
    "appBundleTreeSha256": adhoc["appBundleTreeSha256"],
    "appCodeDirectoryHash": signing["appCodeDirectoryHash"],
    "appExecutableSha256": "b" * 64,
    "appGitSha": archive["appGitSha"],
    "appGitTree": archive["appGitTree"],
    "appPathSha256": "c" * 64,
    "appProvisioningProfileSha256": signing[
        "appProvisioningProfileSha256"
    ],
    "cashuAndPaidExitCompiled": False,
    "companySigningVerified": True,
    "debuggable": False,
    "derivedDataPathSha256": "d" * 64,
    "fipsCoreVersion": archive["fipsCoreVersion"],
    "fipsCargoMetadataReceiptPathSha256": archive[
        "fipsCargoMetadataReceiptPathSha256"
    ],
    "fipsCargoMetadataReceiptSha256": archive[
        "fipsCargoMetadataReceiptSha256"
    ],
    "fipsCheckoutPathSha256": archive["fipsCheckoutPathSha256"],
    "fipsDependenciesForcedRebuilt": True,
    "fipsGitSha": archive["fipsGitSha"],
    "fipsGitTree": archive["fipsGitTree"],
    "installedBundleIdentifier": identity["appBundleIdentifier"],
    "installedBuildNumber": identity["buildNumber"],
    "installedMarketingVersion": identity["marketingVersion"],
    "packetTunnelExecutableSha256": "e" * 64,
    "packetTunnelCodeDirectoryHash": signing[
        "packetTunnelCodeDirectoryHash"
    ],
    "packetTunnelProvisioningProfileSha256": signing[
        "packetTunnelProvisioningProfileSha256"
    ],
    "selectedPhysicalDevice": {
        "deviceIdentifierSha256": "7" * 64,
        "explicitPhysicalDeviceVerified": True,
        "model": "Fixture iPhone",
        "platform": "iOS",
        "productType": "Fixture1,1",
    },
    "selectedPhysicalDeviceIdentifierSha256": "7" * 64,
    "signerCertificateSha256": signing["signerCertificateSha256"],
    "testProductsPathSha256": "f" * 64,
    "testProductsTreeSha256": "0" * 64,
    "treeSha256": adhoc["appBundleTreeSha256"],
    "updaterCompiled": False,
    "paidExitWalletWorkerCompiled": False,
    "xctestrunPathSha256": "1" * 64,
    "xctestrunSha256": "2" * 64,
}
archive_path.write_text(
    json.dumps(archive, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
adhoc["archiveReceiptSha256"] = hashlib.sha256(
    archive_path.read_bytes()
).hexdigest()
for path, payload in ((adhoc_path, adhoc), (mobile_path, mobile)):
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
variant = {
    **mobile,
    "artifactType": "iOS Ad Hoc Release join-test variant",
    "appBundleTreeSha256": "7" * 64,
    "treeSha256": "7" * 64,
    "appCodeDirectoryHash": "8" * 40,
    "appExecutableSha256": "9" * 64,
    "fileSharingFixture": {
        "bundleIdentifier": mobile["installedBundleIdentifier"],
        "displayName": "Nostr VPN Test Files",
        "scope": "join-test-variant-only",
    },
    "joinTestingCompilationCondition": "NVPN_RELEASE_JOIN_TESTING",
    "joinTestingCompilationConditionEnabled": True,
    "productionArtifactReceiptSha256": hashlib.sha256(
        mobile_path.read_bytes()
    ).hexdigest(),
    "productionAppByteIdentical": False,
}
variant_path.write_text(
    json.dumps(variant, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
android_identity = {
    "artifactReceiptSha256": "a" * 64,
    "appGitSha": mobile["appGitSha"],
    "appGitTree": mobile["appGitTree"],
    "fipsGitSha": mobile["fipsGitSha"],
    "fipsGitTree": mobile["fipsGitTree"],
    "apkSha256": "b" * 64,
    "installedApkSha256": "b" * 64,
    "package": "fi.siriusbusiness.nvpn",
    "signerCertificateSha256": "c" * 64,
}
join = {
    "schema": 1,
    "platform": "mobile",
    "coverageScope": "android-ios-mobile-only",
    "harnessGitSha": "8" * 40,
    "harnessGitTree": "9" * 40,
    "artifact": {
        "android": android_identity,
        "ios": {
            **{
                key: variant[key]
                for key in (
                    "appGitSha",
                    "appGitTree",
                    "fipsGitSha",
                    "fipsGitTree",
                    "appBundleTreeSha256",
                    "appCodeDirectoryHash",
                    "packetTunnelCodeDirectoryHash",
                    "appExecutableSha256",
                    "packetTunnelExecutableSha256",
                    "signerCertificateSha256",
                    "installedBundleIdentifier",
                    "fileSharingFixture",
                )
            },
            "artifactReceiptSha256": hashlib.sha256(
                variant_path.read_bytes()
            ).hexdigest(),
            "productionArtifactReceiptSha256": hashlib.sha256(
                mobile_path.read_bytes()
            ).hexdigest(),
            "joinTestingCompilationCondition": "NVPN_RELEASE_JOIN_TESTING",
            "joinTestingCompilationConditionEnabled": True,
            "productionAppByteIdentical": False,
        },
    },
    "publicUiOnly": True,
    "productionImageImportQr": False,
    "iosJoinTestVariant": True,
    "testOnlyImageImportQr": True,
    "productionQrDecoderPath": True,
    "productionJoinApprovalPath": True,
    "productionRosterPath": True,
    "actualRenderedQrScreenCapture": {
        "androidRenderedScreenSha256": "a" * 64,
        "iosRenderedScreenSha256": "b" * 64,
    },
    "privateAppStateRead": False,
    "appLaunchArgumentsOrEnvironment": False,
    "deliveryDeadlineMilliseconds": 15000,
    "deliveryMilliseconds": {
        "iPhone-admin-to-Pixel-QR": 100,
        "Pixel-admin-to-iPhone-QR": 100,
        "iPhone-admin-to-Pixel-manual": 100,
        "Pixel-admin-to-iPhone-manual": 100,
    },
    "contentWidth": {
        "minimumRequiredBasisPoints": 9800,
        "maximumAllowedBasisPoints": 10000,
        "androidObservedBasisPoints": 10000,
        "iosObservedBasisPoints": 10000,
    },
    "qr": {
        "iphoneAdminPixelJoiner": True,
        "pixelAdminIphoneJoiner": True,
        "pendingQrBackgroundForeground": True,
        "exactRosterOnBothSides": True,
        "joinerRelaunchDurable": True,
        "androidJoinerRelaunchDurable": True,
        "iphoneJoinerRelaunchDurable": True,
    },
    "manual": {
        "iphoneAdminPixelJoiner": True,
        "pixelAdminIphoneJoiner": True,
        "exactRosterOnBothSides": True,
        "acceptedRosterOnly": True,
        "iphoneAdminPixelJoinerRelaunchDurable": True,
        "pixelAdminIphoneJoinerRelaunchDurable": True,
    },
}
join_path.write_text(
    json.dumps(join, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
identity_fields = {
    key: mobile[key]
    for key in (
        "appBundleTreeSha256",
        "appCodeDirectoryHash",
        "packetTunnelCodeDirectoryHash",
        "appExecutableSha256",
        "packetTunnelExecutableSha256",
        "signerCertificateSha256",
        "installedBundleIdentifier",
    )
}
join_identity_fields = {
    key: variant[key]
    for key in identity_fields
}
def counter_case():
    return {
        "wireGuardRxBytesBefore": 1,
        "wireGuardRxBytesAfter": 2,
        "wireGuardTxBytesBefore": 1,
        "wireGuardTxBytesAfter": 2,
        "forwardedPacketsBefore": 1,
        "forwardedPacketsAfter": 2,
        "dnsPathCountersBefore": {"query": 1},
        "dnsPathCountersAfter": {"query": 2},
    }
base_network = {
    "receiptSchema": 1,
    "platform": "ios",
    "appGitSha": mobile["appGitSha"],
    "appGitTree": mobile["appGitTree"],
    "fipsGitSha": mobile["fipsGitSha"],
    "fipsGitTree": mobile["fipsGitTree"],
    "artifactIdentity": identity_fields,
    "evidenceFiles": {
        "processes.json": "a" * 64,
        "mobile-ios-network-counter-ledger.tsv": "a" * 64,
    },
}
wg = {
    **base_network,
    "artifactType": "physical ios Release wireguard-dns gate",
    "mode": "wireguard-dns",
    "dnsCases": {
        label: counter_case()
        for label in (
            "automatic-profile",
            "cloudflare-doh",
            "quad9-doh",
            "custom-doh",
            "through-exit",
        )
    },
    "support": {"rapidStartStopCycles": 8},
}
underlay = {
    **base_network,
    "artifactType": "physical ios Release underlay-lifecycle gate",
    "mode": "underlay-lifecycle",
    "evidenceFiles": {
        path: "a" * 64
        for path in (
            "case-continuity.json",
            "case-host-markers.tsv",
            "case-processes.json",
            "case-reverse-payload.log",
            "case-runner-markers.log",
            "mobile-ios-underlay-fresh-dns-fixture.json",
            "mobile-ios-network-counter-ledger.tsv",
        )
    },
    "dnsCases": {"automatic-profile": counter_case()},
    "support": {
        "lifecycleCycles": 3,
        "underlayCycles": [{
            "dnsAndWireGuardRecoveryMilliseconds": 200,
            "firstReversePayloadRecoveryMilliseconds": 200,
            "freshDnsFixtureExactQueryCount": 1,
            "freshDnsQueryHost":
                "12345678-1234-1234-1234-123456789abc.fixture.test",
            "gate": "wifi-radio-off-on-recovery",
            "noValidatedPhysicalFallbackEvidenceCount": 1,
            "originalWifiRestoredEvidenceCount": 1,
            "outageReversePayloads": 0,
            "processIdentifierCounts": {"app": 1, "packetTunnel": 1},
        }],
    },
}
desktop_join = {
    "schema": 1,
    "platform": "macos",
    "artifact": {
        "appGitSha": mobile["appGitSha"],
        "appGitTree": mobile["appGitTree"],
        "android": {
            **android_identity,
            "installReceiptSha256": "d" * 64,
            "installReceiptSize": 1024,
        },
        "ios": {
            "artifactReceiptSha256": hashlib.sha256(
                variant_path.read_bytes()
            ).hexdigest(),
            "appGitSha": variant["appGitSha"],
            "appGitTree": variant["appGitTree"],
            "fipsGitSha": variant["fipsGitSha"],
            "fipsGitTree": variant["fipsGitTree"],
            **join_identity_fields,
        },
    },
    "publicUiOnly": True,
    "privateStateRead": False,
    "fixtureInvoked": False,
    "appLaunchArgumentsOrEnvironment": False,
    "desktopAdminAndroidJoiner": True,
    "androidAdminDesktopJoiner": True,
    "desktopAdminIphoneJoiner": True,
    "iphoneAdminDesktopJoiner": True,
    "acceptedRosterRetainedAcrossRelaunch": True,
    "desktopRelaunchDurability": True,
    "pixelRelaunchDurability": True,
    "desktopAdminIphoneJoinerRelaunchDurable": True,
    "iphoneAdminDesktopJoinerRelaunchDurable": True,
    "deliveryDeadlineMilliseconds": 15000,
    "deliveryMilliseconds": {
        "macOS-admin-to-Android-manual": 100,
        "Android-admin-to-macOS-manual": 100,
        "macOS-admin-to-iPhone-manual": 100,
        "iPhone-admin-to-macOS-manual": 100,
    },
}
for path, payload in (
    (wg_path, wg),
    (underlay_path, underlay),
    (desktop_join_path, desktop_join),
):
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
PY

python3 - \
  "$ROOT" "$MOBILE_RECEIPT" "$MOBILE_WG_RECEIPT" \
  "$MOBILE_UNDERLAY_RECEIPT" <<'PY'
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "scripts"))
from ios_frozen_gate import validate_mobile_network_receipt

mobile = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
wireguard = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
underlay = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
combined = {
    **wireguard,
    "coveredModes": ["wireguard-dns", "underlay-lifecycle"],
    "evidenceFiles": {
        **wireguard["evidenceFiles"],
        **underlay["evidenceFiles"],
    },
    "support": {**wireguard["support"], **underlay["support"]},
}
validate_mobile_network_receipt(combined, mobile, "wireguard-dns")
validate_mobile_network_receipt(combined, mobile, "underlay-lifecycle")
PY

cp "$ARCHIVE_RECEIPT" "$ARCHIVE_CLEAN"
cp "$ADHOC_RECEIPT" "$ADHOC_CLEAN"
cp "$MOBILE_RECEIPT" "$MOBILE_CLEAN"
cp "$JOIN_VARIANT_RECEIPT" "$JOIN_VARIANT_CLEAN"
cp "$MOBILE_JOIN_RECEIPT" "$MOBILE_JOIN_CLEAN"
cp "$DESKTOP_MOBILE_JOIN_RECEIPT" "$DESKTOP_MOBILE_JOIN_CLEAN"

restore_receipts() {
  cp "$ARCHIVE_CLEAN" "$ARCHIVE_RECEIPT"
  cp "$ADHOC_CLEAN" "$ADHOC_RECEIPT"
  cp "$MOBILE_CLEAN" "$MOBILE_RECEIPT"
  cp "$JOIN_VARIANT_CLEAN" "$JOIN_VARIANT_RECEIPT"
  cp "$MOBILE_JOIN_CLEAN" "$MOBILE_JOIN_RECEIPT"
  cp "$DESKTOP_MOBILE_JOIN_CLEAN" "$DESKTOP_MOBILE_JOIN_RECEIPT"
}

GATE_ARGS=(
  --required-gate wireguard-exit-and-five-dns-policies
  --required-gate background-foreground-and-rapid-start-stop
  --required-gate wifi-radio-off-on-recovery
  --required-gate bidirectional-mobile-qr-and-manual-join
  --required-gate desktop-mobile-manual-join
)

seal_gate() {
  python3 "$TOOL" seal-gate \
    --archive-receipt "$ARCHIVE_RECEIPT" \
    --adhoc-receipt "$ADHOC_RECEIPT" \
    --mobile-receipt "$MOBILE_RECEIPT" \
    --mobile-join-ios-variant-receipt "$JOIN_VARIANT_RECEIPT" \
    --mobile-join-receipt "$MOBILE_JOIN_RECEIPT" \
    --mobile-wg-receipt "$MOBILE_WG_RECEIPT" \
    --mobile-underlay-receipt "$MOBILE_UNDERLAY_RECEIPT" \
    --desktop-mobile-join-receipt "$DESKTOP_MOBILE_JOIN_RECEIPT" \
    --sealed-mobile-receipt "$SEALED_MOBILE_RECEIPT" \
    --output "$GATE_SEAL" \
    "${GATE_ARGS[@]}"
}

validate_gate() {
  python3 "$TOOL" validate-gate-seal \
    --archive-receipt "$ARCHIVE_RECEIPT" \
    --adhoc-receipt "$ADHOC_RECEIPT" \
    --sealed-mobile-receipt "$SEALED_MOBILE_RECEIPT" \
    --mobile-join-ios-variant-receipt "$JOIN_VARIANT_RECEIPT" \
    --mobile-join-receipt "$MOBILE_JOIN_RECEIPT" \
    --mobile-wg-receipt "$MOBILE_WG_RECEIPT" \
    --mobile-underlay-receipt "$MOBILE_UNDERLAY_RECEIPT" \
    --desktop-mobile-join-receipt "$DESKTOP_MOBILE_JOIN_RECEIPT" \
    --gate-seal "$GATE_SEAL" \
    "${GATE_ARGS[@]}"
}

python3 - \
  "$ARCHIVE_RECEIPT" "$ADHOC_RECEIPT" "$MOBILE_RECEIPT" <<'PY'
import json
import pathlib
import sys

for path in map(pathlib.Path, sys.argv[1:]):
    value = json.loads(path.read_text(encoding="utf-8"))
    del value["appGitTree"]
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted matching omitted source evidence" >&2
  exit 1
fi
restore_receipts

python3 - "$ARCHIVE_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["rustBuildProfile"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted an archive without a Release Rust profile" >&2
  exit 1
fi
restore_receipts

python3 - "$ADHOC_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["archiveReceiptSha256"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted an omitted archive-receipt link" >&2
  exit 1
fi
restore_receipts

python3 - "$ADHOC_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["archiveReceiptSha256"] = "0" * 64
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted a mismatched archive-receipt link" >&2
  exit 1
fi
restore_receipts

seal_gate
validate_gate
[[ "$(stat -f '%Lp' "$GATE_SEAL" 2>/dev/null || stat -c '%a' "$GATE_SEAL")" == 600 ]] \
  || { echo "Frozen iOS gate seal is not mode 0600" >&2; exit 1; }

python3 - "$JOIN_VARIANT_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["joinTestingCompilationConditionEnabled"] = False
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted a join variant without its compile-time flag" >&2
  exit 1
fi
cp "$JOIN_VARIANT_CLEAN" "$JOIN_VARIANT_RECEIPT"
seal_gate

mobile_wg_ledger_clean="$TMP_ROOT/mobile-wg-ledger.clean"
cp "$MOBILE_WG_RECEIPT" "$mobile_wg_ledger_clean"
python3 - "$MOBILE_WG_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["evidenceFiles"]["mobile-ios-network-counter-ledger.tsv"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted network evidence without its counter ledger" >&2
  exit 1
fi
mv "$mobile_wg_ledger_clean" "$MOBILE_WG_RECEIPT"
seal_gate

python3 - "$MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["coverageScope"] = "android-ios-desktop"
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted a dishonest mobile join coverage scope" >&2
  exit 1
fi
cp "$MOBILE_JOIN_CLEAN" "$MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["contentWidth"]["iosObservedBasisPoints"] = 7500
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted a non-full-width mobile QR receipt" >&2
  exit 1
fi
cp "$MOBILE_JOIN_CLEAN" "$MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["contentWidth"]["androidObservedBasisPoints"] = 10001
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted an impossible oversized QR ratio" >&2
  exit 1
fi
cp "$MOBILE_JOIN_CLEAN" "$MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["qr"]["iphoneJoinerRelaunchDurable"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted QR evidence without iPhone relaunch durability" >&2
  exit 1
fi
cp "$MOBILE_JOIN_CLEAN" "$MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["manual"]["iphoneAdminPixelJoinerRelaunchDurable"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted iPhone-admin manual evidence without relaunch durability" >&2
  exit 1
fi
cp "$MOBILE_JOIN_CLEAN" "$MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["manual"]["pixelAdminIphoneJoinerRelaunchDurable"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted iPhone-joiner manual evidence without relaunch durability" >&2
  exit 1
fi
cp "$MOBILE_JOIN_CLEAN" "$MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$DESKTOP_MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["desktopAdminIphoneJoiner"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted desktop/mobile evidence without the iPhone joiner role" >&2
  exit 1
fi
cp "$DESKTOP_MOBILE_JOIN_CLEAN" "$DESKTOP_MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$DESKTOP_MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["iphoneAdminDesktopJoinerRelaunchDurable"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted iPhone-admin evidence without relaunch durability" >&2
  exit 1
fi
cp "$DESKTOP_MOBILE_JOIN_CLEAN" "$DESKTOP_MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$DESKTOP_MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["artifact"]["ios"]["appCodeDirectoryHash"] = "0" * 40
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted a different iPhone join artifact" >&2
  exit 1
fi
cp "$DESKTOP_MOBILE_JOIN_CLEAN" "$DESKTOP_MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$MOBILE_JOIN_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["deliveryMilliseconds"]["iPhone-admin-to-Pixel-QR"] = 15001
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if validate_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted a stale or slow mobile join receipt" >&2
  exit 1
fi
cp "$MOBILE_JOIN_CLEAN" "$MOBILE_JOIN_RECEIPT"
seal_gate

python3 - "$GATE_SEAL" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["mobileArtifactEvidence"]["appCodeDirectoryHash"] = "0" * 40
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if validate_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted altered physical-artifact evidence" >&2
  exit 1
fi
seal_gate

python3 - "$GATE_SEAL" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
del value["mobileArtifactEvidence"]["fipsGitTree"]
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if validate_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted omitted physical-artifact evidence" >&2
  exit 1
fi
seal_gate

python3 - "$SEALED_MOBILE_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["selectedPhysicalDevice"]["model"] = "Altered iPhone"
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if validate_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted an altered sealed physical receipt" >&2
  exit 1
fi
seal_gate

python3 - "$MOBILE_RECEIPT" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["appProvisioningProfileSha256"] = "0" * 64
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
if seal_gate >/dev/null 2>&1; then
  echo "Frozen iOS gate accepted different physical signing material" >&2
  exit 1
fi

(
  # shellcheck disable=SC1091
  source "$ROOT/scripts/release_common.sh"
  full_head="$(git -C "$ROOT" rev-parse HEAD)"
  NVPN_BUILD_GIT_SHA="$(git_short_sha "$ROOT")"
  pin_exact_release_build_git_sha \
    "$ROOT" "$full_head" "fixture release"
  [[ "$NVPN_BUILD_GIT_SHA" == "$full_head" ]] || {
    echo "Release Git SHA was not normalized before the frozen build" >&2
    exit 1
  }
  NVPN_BUILD_GIT_SHA="000000000000"
  if pin_exact_release_build_git_sha \
    "$ROOT" "$full_head" "fixture release" >/dev/null 2>&1
  then
    echo "Release Git SHA pin accepted an unrelated override" >&2
    exit 1
  fi

  generated_products="$TMP_ROOT/generated-products"
  canonical_plan="$generated_products/NostrVpnIos_fixture.xctestrun"
  external_plan="$TMP_ROOT/external.xctestrun"
  mkdir -p "$generated_products"
  printf 'canonical\n' >"$canonical_plan"
  printf 'external\n' >"$external_plan"
  NVPN_MOBILE_IOS_RELEASE_XCTESTRUN="$external_plan"
  if select_generated_ios_release_xctestrun \
    "$generated_products" "fixture" >/dev/null 2>&1
  then
    echo "Frozen Release accepted an external iOS xctestrun" >&2
    exit 1
  fi
  unset NVPN_MOBILE_IOS_RELEASE_XCTESTRUN
  selected_plan="$(
    select_generated_ios_release_xctestrun \
      "$generated_products" "fixture"
  )"
  [[ "$selected_plan" == "$canonical_plan" ]] || {
    echo "Frozen Release did not select its sole generated xctestrun" >&2
    exit 1
  }
)

python3 - \
  "$ROOT/scripts/ios-build" \
  "$ROOT/scripts/local-release.mjs" \
  "$ROOT/scripts/release-gate.sh" \
  "$ROOT/scripts/lib-mobile-ios-release-network.sh" \
  "$ROOT/scripts/lib-mobile-release-join-ui.sh" \
  "$TOOL" \
  "$ROOT/scripts/ios_xctestrun.py" <<'PY'
import pathlib
import sys

ios_build, local_release, release_gate, network, join, tool, xctestrun = [
    pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
]
for required in (
    "manageAppVersionAndBuildNumber",
    "release-testing",
    "app-store-connect",
    'validate_frozen_gate_seal',
    'app="$(unpack_ipa "$ipa" "$FROZEN_APPSTORE_UNPACK_DIR")"',
):
    if required not in ios_build:
        raise SystemExit(f"frozen iOS build path lacks {required}")
if (
    "<key>manageAppVersionAndBuildNumber</key>\n  <false/>"
    not in ios_build
):
    raise SystemExit("Xcode export may mutate the frozen version or build")
archive = ios_build.split("run_ios_archive() {", 1)[1].split(
    "\nrun_export_archive() {", 1
)[0]
for required in (
    'local NVPN_IOS_RUST_PROFILE="release"',
    "export NVPN_IOS_RUST_PROFILE",
):
    if required not in archive:
        raise SystemExit("frozen archive does not force the Release Rust profile")
if '--rust-profile "$NVPN_IOS_RUST_PROFILE"' not in ios_build:
    raise SystemExit("frozen archive receipt is not bound to its Rust profile")
for required in (
    '"rustBuildProfile": args.rust_profile',
    'args.rust_profile == "release"',
    'receipt.get("rustBuildProfile") == "release"',
):
    if required not in tool:
        raise SystemExit("frozen archive validator does not require Release Rust")
if archive.index("prepare_frozen_revision_args") > archive.index(
    "run_ios_rust"
):
    raise SystemExit("frozen archive builds before pinning the full Git SHA")
if (
    "if ! xcodebuild" not in archive
    or archive.count("restore_generated_ios_project") != 2
    or archive.rindex("restore_generated_ios_project")
    > archive.index("write_frozen_archive_receipt")
):
    raise SystemExit("frozen archive does not restore generated source before freezing")
restore = ios_build.split("restore_generated_ios_project() {", 1)[1].split(
    "\n}", 1
)[0]
if '>"$PROJECT/project.pbxproj"' not in restore:
    raise SystemExit("generated iOS project restore targets the .xcodeproj directory")
recovery = (
    'if [[ -d "$ARCHIVE_PATH" '
    '&& ! -e "$FROZEN_ARCHIVE_RECEIPT" ]]; then'
)
if recovery in archive:
    raise SystemExit("receiptless archive can synthesize Release provenance")
partial_state_guard = (
    'if [[ -e "$ARCHIVE_PATH" || -e "$FROZEN_ARCHIVE_RECEIPT" ]]'
)
if (
    partial_state_guard not in archive
    or archive.index(partial_state_guard) > archive.index("ensure_profiles")
    or "refusing to rebuild over it" not in archive
):
    raise SystemExit("receiptless archive is not rejected before rebuilding")
if 'BUNDLE_ID" == "$NVPN_BUILTIN_IOS_BUNDLE_ID' not in ios_build:
    raise SystemExit("frozen archive permits non-production app identifiers")
if 'NVPN_APP_VERSION_NAME" == "$source_version' not in ios_build:
    raise SystemExit("frozen archive permits an untracked marketing version")
if 'IOS_INTERNAL_ONLY="${NVPN_IOS_INTERNAL_ONLY:-false}"' not in ios_build:
    raise SystemExit("App Store export defaults to internal-only distribution")
if 'NVPN_IOS_RELEASE_SOURCE_ROOT:-$HARNESS_ROOT' not in ios_build:
    raise SystemExit("current iOS harness cannot operate on exact product source")
for current_tool in (
    'source "$HARNESS_ROOT/scripts/release_common.sh"',
    'FROZEN_TOOL="$HARNESS_ROOT/scripts/ios_frozen_archive.py"',
    '"$HARNESS_ROOT/scripts/ios-profiles" ensure',
    'require_release_mutation_gate "$HARNESS_ROOT"',
):
    if current_tool not in ios_build:
        raise SystemExit("exact product export uses historical release tooling")
if 'require_release_mutation_gate "$ROOT"' in ios_build:
    raise SystemExit("iOS publication replays a historical mutation gate")
if ios_build.count('require_release_mutation_gate "$HARNESS_ROOT"') < 4:
    raise SystemExit("not every iOS publication action uses the current mutation gate")
if (
    '--mobile-join-ios-variant-receipt \\\n'
    '      "$FROZEN_MOBILE_JOIN_IOS_VARIANT_RECEIPT"'
) not in ios_build:
    raise SystemExit("frozen gate validation omits the sealed iOS join variant")
release_testing = ios_build.split(
    "run_ios_release_testing_export() {", 1
)[1].split("\nrun_ios_export() {", 1)[0]
reuse = release_testing.split('ensure_dir "$FROZEN_DIR"', 1)[0]
if (
    'app="$(unpack_ipa "$ipa" "$FROZEN_ADHOC_UNPACK_DIR")"'
    not in reuse
):
    raise SystemExit("Ad Hoc reuse validates a stale unpack instead of its IPA")
testflight = ios_build.split("run_ios_testflight() {", 1)[1].split(
    '\ncase "${1:-}"', 1
)[0]
if "run_ios_archive" in testflight:
    raise SystemExit("final iOS release path can rebuild after physical tests")
if "NVPN_RELEASE_IOS_FROZEN_ARCHIVE: '1'" not in local_release:
    raise SystemExit("local release does not require the frozen iOS gate")
if release_gate.index("run_mobile_join_e2e_gate\n") > release_gate.index(
    "seal_frozen_ios_release_gate\n"
):
    raise SystemExit("frozen iOS archive is sealed before the join gate")
full_dns = (
    "NVPN_MOBILE_WG_EXIT_DNS_CASES="
    "automatic-profile,cloudflare-doh,quad9-doh,custom-doh,through-exit"
)
if release_gate.count(full_dns) < 2:
    raise SystemExit("release lanes can inherit a focused DNS subset")
initial_mobile_network = release_gate.split(
    "run_mobile_wireguard_exit_gates() {", 1
)[1].split("\nverify_paid_exit_seller_ui_gates() {", 1)[0]
if "NVPN_MOBILE_WG_EXIT_INSTALL_IOS=1" not in initial_mobile_network:
    raise SystemExit("initial iOS network gate can skip installing its exact build")
if 'NVPN_MOBILE_WG_EXIT_INSTALL_IOS="$((1 - MOBILE_IOS_APP_READY))"' in initial_mobile_network:
    raise SystemExit("iOS app readiness is incorrectly treated as exact artifact reuse")
for pinned in (
    "NVPN_MOBILE_WG_EXIT_REUSE_IOS_BUILD=0",
    "NVPN_IOS_ACTIVE_TUNNEL_LIFECYCLE_CYCLES=1",
    "NVPN_IOS_RELEASE_NETWORK_BACKGROUND_DWELL_SECS=20",
    "NVPN_MOBILE_UNDERLAY_ASSOCIATION_TIMEOUT_SECS=30",
    "NVPN_MOBILE_UNDERLAY_RECOVERY_MAX_MS=4000",
):
    if pinned not in release_gate:
        raise SystemExit(f"release gate does not pin {pinned}")
for oracle in (
    "NVPN_MOBILE_WG_EXIT_DIRECT_HOST=example.com",
    "NVPN_MOBILE_WG_EXIT_DIRECT_URL=https://example.com/",
    "NVPN_MOBILE_WG_EXIT_EXPECTED_SOURCE_IP=",
    "NVPN_MOBILE_WG_EXIT_RELEASE_BLACKBOX=1",
    "NVPN_MOBILE_WG_EXIT_SOURCE_IP_URL=https://api.ipify.org",
):
    if release_gate.count(oracle) < 4:
        raise SystemExit(f"physical release lanes do not pin {oracle}")
for source in (network, join):
    if "rewrite-xctestrun" not in source:
        raise SystemExit("temp xctestrun bypasses the absolute-path rewriter")
    if "--environment-stdin0" not in source:
        raise SystemExit("private xctestrun inputs remain visible in argv")
    if 'cp "$IOS_RELEASE_NETWORK_XCTESTRUN"' in source:
        raise SystemExit("network xctestrun still uses a relocatable raw copy")
    if 'cp "$RELEASE_JOIN_IOS_XCTESTRUN"' in source:
        raise SystemExit("join xctestrun still uses a relocatable raw copy")
for source, label in ((network, "network"), (release_gate, "join gate")):
    if "select_generated_ios_release_xctestrun" not in source:
        raise SystemExit(f"{label} does not select the generated xctestrun")
if "NVPN_MOBILE_IOS_RELEASE_XCTESTRUN" in release_gate:
    raise SystemExit("join gate still trusts an external xctestrun")
if "NVPN_MOBILE_IOS_RELEASE_DERIVED_DATA" in release_gate:
    raise SystemExit("join gate still trusts external iOS test products")
for required in (
    'xctestrun="${NVPN_MOBILE_IOS_RELEASE_XCTESTRUN:-}"',
    'xctestrun_sha="$(shasum -a 256 "$xctestrun"',
    '"xctestrunSha256": xctest_sha',
    '"testProductsTreeSha256": test_products_tree',
):
    if required not in network:
        raise SystemExit(
            f"iOS network reuse does not bind its supplied test plan: {required}"
        )
if "NVPN_MOBILE_IOS_RELEASE_APP_PATH" in release_gate:
    raise SystemExit("join gate still trusts an external frozen-app path")
for required in (
    'target["TestBundlePath"]',
    'target["TestHostPath"]',
    'target["UITargetAppCommandLineArguments"]',
    'target["UITargetAppEnvironmentVariables"]',
    'target["UITargetAppPath"]',
    'target["DependentProductPaths"]',
):
    if required not in xctestrun:
        raise SystemExit(f"xctestrun rewriter omits {required}")
if "from ios_xctestrun import rewrite_xctestrun" not in tool:
    raise SystemExit("frozen archive CLI does not expose the xctestrun rewriter")
PY

python3 - "$TOOL" "$TMP_ROOT/dirty-policy" <<'PY'
import os
import pathlib
import runpy
import sys

tool = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(tool.parent))
module = runpy.run_path(tool)
require_clean = module["require_clean_checkout"]
digest, run = module["sha256_file"], module["run"]


def rejects(repo, label="application"):
    try:
        require_clean(repo, label)
    except ValueError:
        return
    raise SystemExit(f"{label} dirty-checkout policy accepted invalid state")


repo = pathlib.Path(sys.argv[2])
repo.mkdir()
manifest, lock = repo / "Cargo.toml", repo / "Cargo.lock"
manifest.write_text("[package]\nname = \"fixture\"\n", encoding="utf-8")
lock.write_text("version = 3\n", encoding="utf-8")
run(["git", "-C", str(repo), "init", "-q"])
run(["git", "-C", str(repo), "add", "Cargo.toml", "Cargo.lock"])
run(["git", "-C", str(repo), "-c", "user.name=Harness",
     "-c", "user.email=harness.invalid", "commit", "-qm", "fixture"])
lock.write_text("version = 4\n", encoding="utf-8")
os.environ.update({
    "NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED": "1",
    "NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256": digest(manifest),
    "NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256": digest(lock),
})
require_clean(repo, "application")
os.environ["NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256"] = "0" * 64
rejects(repo)
os.environ["NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256"] = digest(lock)
(repo / "extra").write_text("dirty\n", encoding="utf-8")
rejects(repo)
(repo / "extra").unlink()
run(["git", "-C", str(repo), "add", "Cargo.lock"])
rejects(repo)
run(["git", "-C", str(repo), "reset", "-q", "HEAD", "Cargo.lock"])
rejects(repo, "FIPS")
PY

echo "Frozen iOS archive fail-closed harness passed"
