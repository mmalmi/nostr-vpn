#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - \
  "$ROOT/ios/Sources/QRCodeScannerView.swift" \
  "$ROOT/ios/UITests/NostrVpnReleaseJoinUITests.swift" \
  "$ROOT/ios/Sources/AppModel.swift" \
  "$ROOT/ios/NostrVpnIos.xcodeproj/project.pbxproj" \
  "$ROOT/scripts/lib-mobile-release-join-ui.sh" <<'PY'
import pathlib
import sys

scanner, tests, app_model, project, harness = (
    pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
)
for required in (
    "#if NVPN_RELEASE_JOIN_TESTING",
    "private let imageImportEnabled = true",
    "private let imageImportEnabled = false",
):
    if required not in scanner:
        raise SystemExit(f"QR importer lacks compile-time test gating: {required}")
if "NVPN_RELEASE_JOIN_QR_IMAGE_IMPORT" in scanner:
    raise SystemExit("QR importer retains unreliable environment transport")
camera = scanner.split("QRCodeScannerView(", 1)[1].split("VStack(spacing: 10)", 1)[0]
if '.accessibilityIdentifier("qr-scanner-camera")' not in camera:
    raise SystemExit("QR scanner identifier is not scoped to the camera view")
container = scanner.split("VStack(spacing: 10)", 1)[1].split(".fileImporter(", 1)[0]
if '.accessibilityIdentifier("qr-scanner-camera")' in container:
    raise SystemExit("QR scanner identifier leaks onto child controls")

setup = tests.split("override func setUpWithError() throws", 1)[1].split(
    "func testCreateAdminNetworkAndReportPublicValues()", 1
)[0]
import_test = tests.split(
    "func testImportJoinQrImageAndRequireAdminRosterProgress()", 1
)[1].split("func test", 1)[0]
other_tests = tests.replace(import_test, "")

for required in (
    "app.launchEnvironment.isEmpty",
    "app.activate()",
):
    if required not in setup:
        raise SystemExit(f"Ordinary Release activation lacks empty-environment contract: {required}")
if "app.launch()" in setup or "app.terminate()" in setup:
    raise SystemExit("Join setup interrupts the established approval carrier")
durability = tests.split("private func relaunchAndRequireAcceptedRoster", 1)[1].split(
    "private func", 1
)[0]
if durability.index("app.terminate()") > durability.index("app.launch()"):
    raise SystemExit("Join durability must still force a real application restart")
if ".launchEnvironment =" in tests:
    raise SystemExit("QR import still uses the unreliable runtime environment path")
if ".launchEnvironment =" in other_tests:
    raise SystemExit("A non-import release join test sets target-app environment")
for required in (
    "XCTAssertTrue(app.launchEnvironment.isEmpty)",
    'element("qr-scanner-camera").waitForExistence',
    'element("join-request-import-image")',
):
    if required not in import_test:
        raise SystemExit(f"QR import launch contract lacks {required}")
if import_test.index('element("qr-scanner-camera")') > import_test.index(
    'element("join-request-import-image")'
):
    raise SystemExit("Importer is queried before the real scanner is visible")

combined = "\n".join((scanner, tests, app_model, project, harness))
for forbidden in (
    "QRImageImportTestMarker",
    "nvpn-release-join-qr-image-import",
    "RELEASE_JOIN_IOS_QR_IMPORT_MARKER",
    "appGroupDataContainer",
):
    if forbidden in combined:
        raise SystemExit(f"Legacy QR marker transport remains: {forbidden}")
PY

echo "iOS QR image import Ad Hoc gating tests passed"
