#!/usr/bin/env bash
set -euo pipefail

# This harness builds standalone Git fixtures. Do not let the enclosing
# release gate's temporary local-FIPS session make those fixtures look like
# the real checkout (or require its Cargo.toml/Cargo.lock receipts).
unset NVPN_LOCAL_FIPS_PATCH_PRECONFIGURED
unset NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256
unset NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256
unset NVPN_LOCAL_FIPS_SESSION_FIPS_PATH_SHA256
unset NVPN_LOCAL_FIPS_SESSION_FIPS_HEAD
unset NVPN_LOCAL_FIPS_SESSION_FIPS_TREE

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-mobile-provenance.XXXXXX")"
APP_ROOT="$TMP_ROOT/app"
FIPS_ROOT="$TMP_ROOT/fips"
trap 'rm -rf "$TMP_ROOT"' EXIT
mkdir -p "$APP_ROOT" "$FIPS_ROOT/crates/fips-core"
printf 'fixture\n' >"$APP_ROOT/source"
printf '[package]\nname = "nvpn-fips-core"\nversion = "1.2.3"\n' \
  >"$FIPS_ROOT/crates/fips-core/Cargo.toml"
for repo in "$APP_ROOT" "$FIPS_ROOT"; do
  git -C "$repo" init -q
  git -C "$repo" add .
  git -C "$repo" \
    -c user.name=Harness -c user.email=harness.invalid commit -qm fixture
done

# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/release_common.sh"
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib-mobile-android-release-gate.sh"
# shellcheck disable=SC1091
source "$ROOT_DIR/scripts/lib-mobile-ios-release-network.sh"
cat >"$TMP_ROOT/clean-runtime.c" <<'C'
int main(void) {
    return 0;
}
C
cat >"$TMP_ROOT/wallet-runtime.c" <<'C'
const char *nvpn_crash_frame = "paid_exit::wallet_worker";
int main(void) {
    return nvpn_crash_frame[0] == '\0';
}
C
cat >"$TMP_ROOT/updater-runtime.c" <<'C'
void nostr_vpn_update_check(void) {}
void nostr_vpn_update_download(void) {}
int main(void) {
    nostr_vpn_update_check();
    nostr_vpn_update_download();
    return 0;
}
C
xcrun clang "$TMP_ROOT/clean-runtime.c" -o "$TMP_ROOT/clean-runtime"
xcrun clang "$TMP_ROOT/wallet-runtime.c" -o "$TMP_ROOT/wallet-runtime"
xcrun clang "$TMP_ROOT/updater-runtime.c" -o "$TMP_ROOT/updater-runtime"
ios_release_network_audit_forbidden_runtime \
  "$TMP_ROOT/clean-runtime" "clean fixture"
if ios_release_network_audit_forbidden_runtime \
  "$TMP_ROOT/wallet-runtime" "wallet fixture" \
  >"$TMP_ROOT/wallet-runtime.log" 2>&1
then
  echo "iOS artifact audit accepted paid_exit::wallet_worker" >&2
  exit 1
fi
grep -Fq 'paid_exit::wallet_worker' "$TMP_ROOT/wallet-runtime.log"
if ios_release_network_audit_forbidden_runtime \
  "$TMP_ROOT/updater-runtime" "updater fixture" \
  >"$TMP_ROOT/updater-runtime.log" 2>&1
then
  echo "iOS artifact audit accepted updater entry points" >&2
  exit 1
fi
grep -Fq 'nostr_vpn_update_check' "$TMP_ROOT/updater-runtime.log"
ROOT="$APP_ROOT"
PACKAGE_NAME=fi.siriusbusiness.nvpn
CANONICAL_PACKAGE_NAME="$PACKAGE_NAME"
ANDROID_KEYSTORE_PATH="$TMP_ROOT/release.keystore"
ANDROID_KEYSTORE_PASSWORD=secret
ANDROID_KEY_ALIAS=release
ANDROID_KEY_PASSWORD=secret
NVPN_FIPS_REPO_PATH="$FIPS_ROOT"
NVPN_IOS_EXPECTED_DEVICE_NAME="Expected phone"
NVPN_BUILD_GIT_SHA=""
printf 'keystore\n' >"$ANDROID_KEYSTORE_PATH"

unset NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256 NVPN_EXPECTED_FIPS_GIT_SHA
if android_release_require_inputs >"$TMP_ROOT/android-missing.log" 2>&1; then
  echo "Android provenance accepted missing external pins" >&2
  exit 1
fi
grep -Fq 'requires NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256' \
  "$TMP_ROOT/android-missing.log"

mkdir -p "$TMP_ROOT/bin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  "printf 'fixture signer certificate'" \
  >"$TMP_ROOT/bin/keytool"
chmod +x "$TMP_ROOT/bin/keytool"
export PATH="$TMP_ROOT/bin:$PATH"
NVPN_EXPECTED_ANDROID_SIGNER_CERT_SHA256="$(
  printf 'fixture signer certificate' | shasum -a 256 | awk '{print $1}'
)"
NVPN_EXPECTED_FIPS_GIT_SHA=0000000000000000000000000000000000000000
if android_release_require_inputs >"$TMP_ROOT/android-fips.log" 2>&1; then
  echo "Android provenance accepted the wrong FIPS revision" >&2
  exit 1
fi
grep -Fq 'Android Release black-box FIPS mismatch' \
  "$TMP_ROOT/android-fips.log"

unset NVPN_EXPECTED_IOS_DISTRIBUTION_TEAM_ID
unset NVPN_EXPECTED_IOS_DISTRIBUTION_CERT_SHA256
unset NVPN_EXPECTED_FIPS_GIT_SHA
if ios_release_network_prepare selected >"$TMP_ROOT/ios-team.log" 2>&1; then
  echo "iOS provenance accepted a missing team pin" >&2
  exit 1
fi
grep -Fq 'requires an exact distribution team pin' "$TMP_ROOT/ios-team.log"

NVPN_EXPECTED_IOS_DISTRIBUTION_TEAM_ID=ABCDE12345
if ios_release_network_prepare selected >"$TMP_ROOT/ios-cert.log" 2>&1; then
  echo "iOS provenance accepted a missing certificate pin" >&2
  exit 1
fi
grep -Fq 'requires an exact distribution certificate SHA-256 pin' \
  "$TMP_ROOT/ios-cert.log"

NVPN_EXPECTED_IOS_DISTRIBUTION_CERT_SHA256="$(
  printf 'certificate' | shasum -a 256 | awk '{print $1}'
)"
if ios_release_network_prepare selected >"$TMP_ROOT/ios-fips.log" 2>&1; then
  echo "iOS provenance accepted a missing FIPS pin" >&2
  exit 1
fi
grep -Fq 'requires an exact FIPS Git SHA pin' "$TMP_ROOT/ios-fips.log"

receipt="$TMP_ROOT/receipt.json"
info="$TMP_ROOT/Info.plist"
installed="$TMP_ROOT/installed.json"
device="$TMP_ROOT/device.json"
receipt_app="$TMP_ROOT/receipt-app/Nostr VPN.app"
receipt_derived="$TMP_ROOT/receipt-derived"
receipt_xctestrun="$receipt_derived/Build/Products/NostrVpnIos_fixture.xctestrun"
mkdir -p \
  "$receipt_app/PlugIns/Nostr VPN Tunnel.appex" \
  "$receipt_derived/Build/Products"
printf 'app profile\n' >"$receipt_app/embedded.mobileprovision"
printf 'tunnel profile\n' \
  >"$receipt_app/PlugIns/Nostr VPN Tunnel.appex/embedded.mobileprovision"
printf 'app executable\n' >"$receipt_app/Nostr VPN"
printf 'tunnel executable\n' \
  >"$receipt_app/PlugIns/Nostr VPN Tunnel.appex/Nostr VPN Tunnel"
python3 - "$info" "$installed" "$device" "$receipt_xctestrun" <<'PY'
import json
import plistlib
import sys

info, installed, device, xctestrun = sys.argv[1:]
with open(info, "wb") as handle:
    plistlib.dump(
        {
            "CFBundleIdentifier": "fi.siriusbusiness.nvpn",
            "CFBundleShortVersionString": "4.1.5",
            "CFBundleVersion": "415",
        },
        handle,
    )
with open(installed, "w", encoding="utf-8") as handle:
    json.dump({}, handle)
with open(device, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "deviceIdentifierSha256": "a" * 64,
            "explicitPhysicalDeviceVerified": True,
            "model": "Fixture Phone",
            "platform": "iOS",
            "productType": "Fixture1,1",
        },
        handle,
    )
with open(xctestrun, "wb") as handle:
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
PY
cp "$info" "$receipt_app/Info.plist"
hash64=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
app_head="$(git -C "$APP_ROOT" rev-parse HEAD)"
app_tree="$(git -C "$APP_ROOT" rev-parse HEAD^{tree})"
fips_head="$(git -C "$FIPS_ROOT" rev-parse HEAD)"
fips_tree="$(git -C "$FIPS_ROOT" rev-parse HEAD^{tree})"
receipt_metadata="$TMP_ROOT/fips-linkage.json"
python3 - "$receipt_metadata" "$FIPS_ROOT" "$fips_head" "$fips_tree" <<'PY'
import hashlib
import json
import os
import sys

path, checkout, head, tree = sys.argv[1:]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "checkoutPathSha256": hashlib.sha256(
                os.path.realpath(checkout).encode()
            ).hexdigest(),
            "checkoutHead": head,
            "checkoutTree": tree,
            "fipsCoreVersion": "1.2.3",
        },
        handle,
        sort_keys=True,
    )
PY
app_binary_sha="$(shasum -a 256 "$receipt_app/Nostr VPN" | awk '{print $1}')"
tunnel_binary_sha="$(
  shasum -a 256 \
    "$receipt_app/PlugIns/Nostr VPN Tunnel.appex/Nostr VPN Tunnel" \
    | awk '{print $1}'
)"
app_bundle_tree="$(
  python3 "$ROOT_DIR/scripts/mobile_release_artifact_receipt.py" \
    tree-sha "$receipt_app"
)"
test_products_tree="$(
  python3 "$ROOT_DIR/scripts/mobile_release_artifact_receipt.py" \
    tree-sha "$receipt_derived/Build/Products"
)"
metadata_sha="$(shasum -a 256 "$receipt_metadata" | awk '{print $1}')"
metadata_path_sha="$(
  python3 -c \
    'import hashlib,os,sys; print(hashlib.sha256(os.path.realpath(sys.argv[1]).encode()).hexdigest())' \
    "$receipt_metadata"
)"
fips_path_sha="$(
  python3 -c \
    'import hashlib,os,sys; print(hashlib.sha256(os.path.realpath(sys.argv[1]).encode()).hexdigest())' \
    "$FIPS_ROOT"
)"
if ios_release_network_write_artifact_receipt \
  "$receipt" cdhash tunnelcd "$app_binary_sha" "$tunnel_binary_sha" \
  "$app_bundle_tree" "$test_products_tree" \
  "$app_head" "$app_tree" "$fips_head" "$info" "$installed" fi.siriusbusiness.nvpn \
  "$device" "$receipt_app" "$receipt_derived" "$receipt_xctestrun" \
  "$fips_tree" 1.2.3 "$metadata_sha" "$metadata_path_sha" \
  "$fips_path_sha" "$hash64" >/dev/null 2>&1
then
  echo "iOS artifact receipt accepted a missing installed app" >&2
  exit 1
fi
[[ ! -e "$receipt" ]]

python3 - "$installed" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(
        {
            "bundleIdentifier": "fi.siriusbusiness.nvpn",
            "builtByDeveloper": True,
            "removable": True,
            "version": "4.1.5",
            "bundleVersion": "415",
        },
        handle,
    )
PY
ios_release_network_write_artifact_receipt \
  "$receipt" cdhash tunnelcd "$app_binary_sha" "$tunnel_binary_sha" \
  "$app_bundle_tree" "$test_products_tree" \
  "$app_head" "$app_tree" "$fips_head" "$info" "$installed" fi.siriusbusiness.nvpn \
  "$device" "$receipt_app" "$receipt_derived" "$receipt_xctestrun" \
  "$fips_tree" 1.2.3 "$metadata_sha" "$metadata_path_sha" \
  "$fips_path_sha" "$hash64"
python3 - "$receipt" "$hash64" <<'PY'
import json
import sys

receipt = json.load(open(sys.argv[1], encoding="utf-8"))
if receipt.get("signerCertificateSha256") != sys.argv[2]:
    raise SystemExit("iOS artifact receipt omitted the signer certificate pin")
if receipt.get("cashuAndPaidExitCompiled") is not False:
    raise SystemExit("iOS artifact receipt omitted Cashu/paid-exit exclusion")
if receipt.get("paidExitWalletWorkerCompiled") is not False:
    raise SystemExit("iOS artifact receipt omitted crash-path exclusion")
if receipt.get("updaterCompiled") is not False:
    raise SystemExit("iOS artifact receipt omitted updater exclusion")
for required in (
    "appGitTree",
    "appBundleTreeSha256",
    "testProductsTreeSha256",
    "xctestrunSha256",
    "appProvisioningProfileSha256",
    "packetTunnelProvisioningProfileSha256",
    "selectedPhysicalDeviceIdentifierSha256",
    "fipsCargoMetadataReceiptPathSha256",
):
    if required not in receipt:
        raise SystemExit(f"iOS artifact receipt omitted {required}")
PY
python3 "$ROOT_DIR/scripts/mobile_release_artifact_receipt.py" \
  validate-ios \
  --receipt "$receipt" \
  --app "$receipt_app" \
  --derived-data "$receipt_derived" \
  --xctestrun "$receipt_xctestrun" \
  --fips-metadata "$receipt_metadata" \
  --fips-root "$FIPS_ROOT" \
  --app-head "$app_head" \
  --app-tree "$app_tree" \
  --fips-head "$fips_head" \
  --fips-tree "$fips_tree" \
  --fips-version 1.2.3 \
  --bundle fi.siriusbusiness.nvpn \
  --signer-sha "$hash64" \
  --app-cdhash cdhash \
  --tunnel-cdhash tunnelcd \
  --device-identifier-sha "$hash64"
grep -Fq 'if ! ios_release_network_write_artifact_receipt' \
  "$ROOT_DIR/scripts/lib-mobile-ios-release-artifact.sh"
grep -Fq 'actual_signer_sha != expected_signer_sha' \
  "$ROOT_DIR/scripts/lib-mobile-ios-release-artifact.sh"

IOS_RELEASE_NETWORK_SIGNING_DIR="$(
  mktemp -d "$TMP_ROOT/nvpn-ios-release-signing.XXXXXX"
)"
IOS_RELEASE_NETWORK_SIGNING_ENV="$IOS_RELEASE_NETWORK_SIGNING_DIR/provisioning.env"
IOS_RELEASE_NETWORK_DEVICE_RECEIPT="$IOS_RELEASE_NETWORK_SIGNING_DIR/device.json"
IOS_RELEASE_NETWORK_CASE_XCTESTRUN="$IOS_RELEASE_NETWORK_SIGNING_DIR/case.xctestrun"
printf 'private profile\n' >"$IOS_RELEASE_NETWORK_SIGNING_ENV"
printf 'private device\n' >"$IOS_RELEASE_NETWORK_DEVICE_RECEIPT"
printf 'private spec\n' >"$IOS_RELEASE_NETWORK_CASE_XCTESTRUN"
private_signing_dir="$IOS_RELEASE_NETWORK_SIGNING_DIR"
ios_release_network_cleanup_private_artifacts
[[ ! -e "$private_signing_dir" ]]
[[ -z "$IOS_RELEASE_NETWORK_SIGNING_DIR" ]]
[[ -z "$IOS_RELEASE_NETWORK_DEVICE_RECEIPT" ]]

echo "mobile Release provenance harness passed"
