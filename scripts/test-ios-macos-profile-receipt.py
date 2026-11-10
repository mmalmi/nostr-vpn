#!/usr/bin/env python3
"""Exercise the real iOS seal consumer and shared Mac proof validator offline."""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

from ios_frozen_gate import validate_desktop_mobile_join_receipt


def identity(fields):
    return {field: "a" * 64 for field in fields.split()}


ios = identity("appGitSha appGitTree fipsGitSha fipsGitTree appBundleTreeSha256 "
               "appCodeDirectoryHash packetTunnelCodeDirectoryHash appExecutableSha256 "
               "packetTunnelExecutableSha256 signerCertificateSha256 installedBundleIdentifier")
android = identity("appGitSha appGitTree fipsGitSha fipsGitTree apkSha256 "
                   "installedApkSha256 package signerCertificateSha256 artifactReceiptSha256")
legacy = {
    "schema": 1, "platform": "macos", "publicUiOnly": True,
    "privateStateRead": False, "fixtureInvoked": False,
    "appLaunchArgumentsOrEnvironment": False,
    "artifact": {"android": {**android, "installReceiptSha256": "b" * 64,
                              "installReceiptSize": 1024},
                 "ios": {**ios, "artifactReceiptSha256": "c" * 64}},
    "deliveryDeadlineMilliseconds": 15000,
    "deliveryMilliseconds": {name: 100 for name in (
        "macOS-admin-to-Android-manual", "Android-admin-to-macOS-manual",
        "macOS-admin-to-iPhone-manual", "iPhone-admin-to-macOS-manual")},
    **{field: True for field in (
        "desktopAdminAndroidJoiner", "androidAdminDesktopJoiner", "desktopAdminIphoneJoiner",
        "iphoneAdminDesktopJoiner", "acceptedRosterRetainedAcrossRelaunch",
        "desktopRelaunchDurability", "pixelRelaunchDurability",
        "desktopAdminIphoneJoinerRelaunchDurable", "iphoneAdminDesktopJoinerRelaunchDurable")},
}
modern = copy.deepcopy(legacy)
modern.update(schema=2, appLaunchArgumentsOrEnvironment=True, selectedDirections="all",
              privateAppStateRead=False, buildOrigin="github-actions", directionEvidence={})
modern["artifact"].update(artifactReceiptSha256="d" * 64, appExecutableSha256="e" * 64)
proof = modern["profileIsolation"] = {
    "schema": 1, "kind": "macos-production-data-directory",
    "environmentKeys": ["HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "NVPN_APP_DATA_DIR"],
    "appArguments": [], "artifactReceiptSha256": "d" * 64,
    "appExecutableSha256": "e" * 64, "directions": {},
}
for direction in ("macosAdminPixelJoiner", "pixelAdminMacosJoiner",
                  "macosAdminIphoneJoiner", "iphoneAdminMacosJoiner"):
    binding = {"runtimeHarnessGitSha": "a" * 40, **identity(
        "runtimeLaunchHelperSha256 outcomeSha256 operationSha256 restoredBaselineIdentitySha256")}
    modern["directionEvidence"][direction] = binding.copy()
    proof["directions"][direction] = {**binding, **identity(
        "configDirectoryBeforeSha256 configDirectoryAfterSha256 configBeforeSha256 "
        "configAfterSha256 systemBeforeSha256 systemAfterSha256"),
        **{name: {key: False for key in ("appOwnership", "externalHarness", "profileTransaction", "testConfig")}
           for name in ("knownPathsBefore", "knownPathsAfter")}}


def validate(receipt):
    validate_desktop_mobile_join_receipt(receipt, ios, "c" * 64, {"artifact": {"android": android}})


validate(legacy)
validate(modern)
cases = []
missing = copy.deepcopy(modern); del missing["profileIsolation"]; cases.append(missing)
false = copy.deepcopy(modern); false["appLaunchArgumentsOrEnvironment"] = False; cases.append(false)
extra = copy.deepcopy(modern); extra["profileIsolation"]["environmentKeys"].append("NVPN_CLI_PATH"); cases.append(extra)
role = copy.deepcopy(modern); del role["profileIsolation"]["directions"]["iphoneAdminMacosJoiner"]; cases.append(role)
downgrade = copy.deepcopy(legacy); downgrade["buildOrigin"] = "github-actions"; cases.append(downgrade)
scope = copy.deepcopy(modern); scope["selectedDirections"] = "pixel"; cases.append(scope)
for receipt in cases:
    try:
        validate(receipt)
    except ValueError:
        pass
    else:
        raise AssertionError("iOS seal accepted invalid Mac launch/profile evidence")
print("PASS: actual iOS seal consumer accepts modern and legacy receipts; six malformed/downgrade/scope cases rejected; no device/build calls")

# Run the actual embedded final writer using synthetic, local receipt fixtures.
root = pathlib.Path(__file__).resolve().parent.parent
source = (root / "scripts/macos-vm-release-mobile-join-e2e.sh").read_text()
section = source[source.index('python3 - \\\n  "$RESULT_DIR/macos/summary.json"'):]
writer = compile(section.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0], "canonical Mac receipt writer", "exec")

with tempfile.TemporaryDirectory(prefix="nvpn-mac-retained-proof-") as temporary:
    directory = pathlib.Path(temporary)

    def save(name, value):
        target = directory / name
        target.write_text(json.dumps(value, sort_keys=True) + "\n")
        return target

    def digest(target):
        return hashlib.sha256(target.read_bytes()).hexdigest()

    mac = save("artifact.json", {
        "receiptSchema": 1, "builtOnHost": True, "builtOnTestVm": False,
        "companySigningVerified": True, "appExecutableSha256": "e" * 64,
        "appGitSha": "a" * 40, "appGitTree": "b" * 40,
        "componentInputProof": {"candidate_app_git_sha": "a" * 40,
                                "candidate_app_git_tree": "b" * 40},
    })
    android_path = save("android.json", {**android, "receiptSchema": 2,
                                         "artifactType": "Android Release APK"})
    install = save("install.json", android)
    variant = save("ios.json", {**ios, "receiptSchema": 2,
                                "artifactType": "iOS Ad Hoc Release join-test variant",
                                "companySigningVerified": True})
    verification = save("verification.json", {"receiptSchema": 1, "remoteImportVerified": True,
                                               "artifactReceiptSha256": digest(mac)})
    full = copy.deepcopy(modern)
    full["artifact"]["artifactReceiptSha256"] = digest(mac)
    full["profileIsolation"]["artifactReceiptSha256"] = digest(mac)
    pixel_roles = ("macosAdminPixelJoiner", "pixelAdminMacosJoiner")
    full["directionEvidence"][pixel_roles[0]].update(
        originalOverallAttemptStatus="failed", standaloneDirectionExitCode=None,
        timingBasis="retained host observation; original start not separately persisted")
    timings = directory / "delivery-times.tsv"
    pixel_evidence = {"profileIsolation": copy.deepcopy(full["profileIsolation"]),
                      "directionEvidence": {role: full["directionEvidence"][role] for role in pixel_roles}}
    pixel_evidence["profileIsolation"]["directions"] = {
        role: full["profileIsolation"]["directions"][role] for role in pixel_roles}
    evidence_path = save("pixel-evidence.json", pixel_evidence)
    timings.write_text("macOS-admin-to-Android-manual\t100\nAndroid-admin-to-macOS-manual\t100\n")
    retained_path = directory / "reused-pixel-summary.json"
    sys.argv = ["writer", str(retained_path), str(timings), str(mac), "", "0", "0",
                "a" * 40, "b" * 40, str(android_path), str(install), "pixel", "",
                str(root), str(verification), str(evidence_path)]
    exec(writer, {})
    retained = json.loads(retained_path.read_text())

    def compose(evidence, output="summary.json", changed_timing=False):
        timings.write_text("".join(f"{label}\t{101 if changed_timing and label == 'macOS-admin-to-Android-manual' else elapsed}\n"
                                  for label, elapsed in full["deliveryMilliseconds"].items()))
        evidence_path = save("profile-evidence.json", {
            "profileIsolation": evidence["profileIsolation"], "directionEvidence": evidence["directionEvidence"]})
        sys.argv = ["writer", str(directory / output), str(timings), str(mac), str(variant),
                    "1", "1", "a" * 40, "b" * 40, str(android_path), str(install), "all",
                    digest(retained_path), str(root), str(verification), str(evidence_path)]
        exec(writer, {})

    compose(full)
    result = json.loads((directory / "summary.json").read_text())
    assert result["reusedPixelReceiptSha256"] == digest(retained_path)
    for role in pixel_roles:
        assert result["profileIsolation"]["directions"][role] == retained["profileIsolation"]["directions"][role]
        assert result["directionEvidence"][role] == retained["directionEvidence"][role]
    for role in pixel_roles:
        replacement = copy.deepcopy(full)
        for key in ("runtimeHarnessGitSha", "runtimeLaunchHelperSha256", "outcomeSha256", "operationSha256"):
            value = "f" * (40 if key == "runtimeHarnessGitSha" else 64)
            replacement["profileIsolation"]["directions"][role][key] = value
            replacement["directionEvidence"][role][key] = value
        # Prove the substitution is internally consistent, so only binding to
        # the retained receipt can reject it at the final writer boundary.
        checked = subprocess.run(["node", "--input-type=module", "-e",
            "import{readFileSync}from'node:fs';import{pathToFileURL}from'node:url';"
            "const{validateMacosJoinProfileIsolation}=await import(pathToFileURL(process.argv[1]));"
            "const r=JSON.parse(readFileSync(0,'utf8'));validateMacosJoinProfileIsolation(r,r.artifact,r.artifact.artifactReceiptSha256);",
            str(root / "scripts/release-artifact-provenance-lib.mjs")],
            input=json.dumps(replacement), text=True, capture_output=True, timeout=15)
        assert checked.returncode == 0, checked.stderr
        try:
            compose(replacement, "rejected.json")
        except SystemExit as error:
            assert "Retained Mac/Pixel launch/profile evidence changed" in str(error)
        else:
            raise AssertionError("canonical writer accepted substituted retained Pixel evidence")
        assert not (directory / "rejected.json").exists()
    try:
        compose(full, "rejected.json", changed_timing=True)
    except SystemExit as error:
        assert "Retained Mac/Pixel delivery timing changed" in str(error)
    else:
        raise AssertionError("canonical writer accepted changed retained Pixel timing")
print("PASS: actual canonical writer preserves both retained Pixel rows; internally consistent replacements for either role and changed timing rejected")
