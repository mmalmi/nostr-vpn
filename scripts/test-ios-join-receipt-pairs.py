#!/usr/bin/env python3
"""Exercise frozen-seal receipt pairing using the existing JSON fixture only."""
import copy
import hashlib
import json
import pathlib
import re
import os
import subprocess
import sys
import tempfile

from ios_frozen_archive import parser
from ios_frozen_gate import REQUIRED_REAL_DEVICE_GATES, seal_gate, validate_gate_seal

ROOT = pathlib.Path(__file__).resolve().parent


def load(path):
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


with tempfile.TemporaryDirectory(prefix="nvpn-ios-receipt-pairs-") as temporary:
    root = pathlib.Path(temporary)
    names = ("archive", "adhoc", "mobile", "variant", "mobile-join", "wg", "underlay", "desktop-join")
    paths = {name: root / f"{name}.json" for name in names}
    # Reuse the existing pure JSON fixture; none of its product/runner setup runs.
    fixture = (ROOT / "test-ios-frozen-archive-harness.sh").read_text().split(
        '"$MOBILE_UNDERLAY_RECEIPT" "$DESKTOP_MOBILE_JOIN_RECEIPT" <<\'PY\'\n', 1,
    )[1].split("\nPY\n", 1)[0]
    fixture = fixture.replace("archive_path.write_text(", '''mobile.update({
    "selectedPhysicalDevice": {**mobile["selectedPhysicalDevice"],
        "identityReadAt": "2026-01-01T00:00:00Z", "identityReadbackSha256": "1" * 64,
        "hardware": {"model": "Fixture"}},
    "derivedDataPathSha256": "3" * 64,
})
archive_path.write_text(''', 1)
    argv = sys.argv
    try:
        sys.argv = ["fixture", *map(str, paths.values())]
        exec(compile(fixture, "<existing frozen seal JSON fixture>", "exec"), {})
    finally:
        sys.argv = argv
    sealed = root / "sealed-mobile.json"
    seal = root / "seal.json"
    common = ["--archive-receipt", str(paths["archive"]), "--adhoc-receipt", str(paths["adhoc"]),
              "--mobile-join-ios-variant-receipt", str(paths["variant"]),
              "--mobile-join-receipt", str(paths["mobile-join"]),
              "--mobile-wg-receipt", str(paths["wg"]),
              "--mobile-underlay-receipt", str(paths["underlay"]),
              "--desktop-mobile-join-receipt", str(paths["desktop-join"]),
              "--sealed-mobile-receipt", str(sealed)]
    for gate in REQUIRED_REAL_DEVICE_GATES:
        common += ["--required-gate", gate]

    def create(extra=()):
        seal_gate(parser().parse_args(["seal-gate", *common,
            "--mobile-receipt", str(paths["mobile"]), "--output", str(seal), *extra]))

    def validate(extra=()):
        validate_gate_seal(parser().parse_args(["validate-gate-seal", *common,
            "--gate-seal", str(seal), *extra]))

    create()
    validate()

    # Exercise the actual release/export shell callsites with a recording
    # Python command: both optional paths travel together, or neither does.
    pair_dir = root / "macos"
    pair_dir.mkdir()
    args_path = root / "shell-args.txt"
    shell_env = dict(os.environ, ROOT_DIR=str(root),
        NVPN_RELEASE_JOIN_RESULT_DIR=str(root), NVPN_RELEASE_IOS_FROZEN_ARCHIVE="1",
        NVPN_RELEASE_GATE_MOBILE_WG_EXIT_E2E="1", NVPN_RELEASE_GATE_MOBILE_UNDERLAY_E2E="1",
        NVPN_RELEASE_GATE_MOBILE_JOIN_E2E="1", NVPN_MOBILE_IOS_RELEASE_RECEIPT=str(paths["mobile"]),
        RELEASE_GATE_PARALLEL_LOG_DIR=str(root), ARGS_OUT=str(args_path),
        FROZEN_DESKTOP_MOBILE_JOIN_RECEIPT=str(pair_dir / "summary.json"),
        FROZEN_TOOL=str(ROOT / "ios_frozen_archive.py"))
    for key in ("FROZEN_ARCHIVE_RECEIPT", "FROZEN_ADHOC_RECEIPT", "FROZEN_MOBILE_RECEIPT",
                "FROZEN_MOBILE_JOIN_IOS_VARIANT_RECEIPT", "FROZEN_MOBILE_JOIN_RECEIPT",
                "FROZEN_MOBILE_WG_RECEIPT", "FROZEN_MOBILE_UNDERLAY_RECEIPT", "FROZEN_GATE_SEAL"):
        shell_env[key] = str(root / key)
    for file, name in (("release-gate.sh", "seal_frozen_ios_release_gate"),
                       ("ios-build", "validate_frozen_gate_seal")):
        source = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n",
                           (ROOT / file).read_text(), re.M | re.S)[0]
        for paired in (False, True):
            for directory, filename in ((pair_dir, "ios-join-test-variant.json"),
                                        (pair_dir, "ios-join-production-artifact.json"),
                                        (root, "android-release-artifact.json"),
                                        (pair_dir, "android-release-artifact.json")):
                path = directory / filename
                if paired:
                    path.write_text("{}\n")
                else:
                    path.unlink(missing_ok=True)
            shell = ('set -euo pipefail\n' + source + '\n'
                'bool_is_true() { [[ "$1" == 1 ]]; }\n'
                'frozen_gate_arguments() { FROZEN_GATE_ARGS=(--fixture); }\n'
                'python3() { printf "%s\\n" "$@" >"$ARGS_OUT"; }\n' + name)
            result = subprocess.run(["bash", "-c", shell], env=shell_env,
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode == 0, result.stderr
            arguments = args_path.read_text().splitlines()
            for flag, filename in (("--desktop-join-ios-variant-receipt", "ios-join-test-variant.json"),
                                   ("--desktop-join-ios-production-receipt", "ios-join-production-artifact.json")):
                assert (flag in arguments) == paired
                if paired:
                    assert arguments[arguments.index(flag) + 1] == str(pair_dir / filename)
            for flag, directory in (("--mobile-join-android-receipt", root),
                                    ("--desktop-join-android-receipt", pair_dir)):
                assert (flag in arguments) == paired
                if paired:
                    assert arguments[arguments.index(flag) + 1] == str(directory / "android-release-artifact.json")
    original_bytes = {name: path.read_bytes() for name, path in paths.items()}
    production = load(paths["mobile"])
    variant = load(paths["variant"])
    desktop = load(paths["desktop-join"])
    production_path = root / "desktop-production.json"
    variant_path = root / "desktop-variant.json"
    extra = ["--desktop-join-ios-variant-receipt", str(variant_path),
             "--desktop-join-ios-production-receipt", str(production_path)]
    new_production = copy.deepcopy(production)
    new_production["selectedPhysicalDevice"].update(
        identityReadAt="2026-01-02T00:00:00Z", identityReadbackSha256="2" * 64)
    new_variant = copy.deepcopy(variant)
    new_variant["selectedPhysicalDevice"] = copy.deepcopy(new_production["selectedPhysicalDevice"])
    for field in ("derivedDataPathSha256", "testProductsPathSha256", "testProductsTreeSha256",
                  "xctestrunPathSha256", "xctestrunSha256"):
        new_variant[field] = "4" * 64

    def install_pair(production_value, variant_value, *, bad_reference=False):
        write(production_path, production_value)
        current = copy.deepcopy(variant_value)
        current["productionArtifactReceiptSha256"] = (
            sha(paths["mobile"]) if bad_reference else sha(production_path))
        write(variant_path, current)
        gate = copy.deepcopy(desktop)
        gate["artifact"]["ios"]["artifactReceiptSha256"] = sha(variant_path)
        write(paths["desktop-join"], gate)

    install_pair(new_production, new_variant)
    create(extra)
    validate(extra)
    good_seal = load(seal)
    assert good_seal["realDeviceGateReceiptSha256"]["desktop-mobile-manual-join"][1] == sha(variant_path)
    assert good_seal["mobileJoinIosVariantReceiptSha256"] == sha(paths["variant"])

    def rebind_seal():
        value = copy.deepcopy(good_seal)
        value["mobileArtifactReceiptSha256"] = sha(paths["mobile"])
        value["mobileJoinIosVariantReceiptSha256"] = sha(paths["variant"])
        value["mobileJoinReceiptSha256"] = sha(paths["mobile-join"])
        value["realDeviceGateReceiptSha256"]["bidirectional-mobile-qr-and-manual-join"] = [
            sha(paths["mobile-join"]), sha(paths["variant"])]
        value["desktopJoinIosVariantReceiptSha256"] = sha(variant_path)
        value["desktopJoinIosProductionReceiptSha256"] = sha(production_path)
        value["desktopMobileJoinReceiptSha256"] = sha(paths["desktop-join"])
        value["realDeviceGateReceiptSha256"]["desktop-mobile-manual-join"] = [
            sha(paths["desktop-join"]), sha(variant_path)]
        write(seal, value)

    def reject(operation, pattern):
        try:
            operation(extra)
        except ValueError as error:
            assert re.search(pattern, str(error)), str(error)
        else:
            raise AssertionError("invalid receipt pair was accepted")

    cases = [
        ("production flag", "production", lambda v: v.update(updaterCompiled=True), "iOS production receipts"),
        ("device", "production", lambda v: v["selectedPhysicalDevice"]["hardware"].update(model="Different"), "iOS production receipts"),
        ("missing identity", "variant", lambda v: v["selectedPhysicalDevice"].pop("deviceIdentifierSha256"), "iOS join variant receipts"),
        ("variant product", "variant", lambda v: v.update(treeSha256="f" * 64), "iOS join variant receipts"),
        ("missing runner key", "variant", lambda v: v.pop("testProductsTreeSha256"), "iOS join variant receipts"),
        ("added field", "variant", lambda v: v.update(unrecognizedIdentity=True), "iOS join variant receipts"),
    ]
    for label, target, mutate, pattern in cases:
        p, v = copy.deepcopy(new_production), copy.deepcopy(new_variant)
        mutate(p if target == "production" else v)
        install_pair(p, v)
        rebind_seal()
        reject(create, pattern)
        reject(validate, pattern)
    install_pair(new_production, new_variant, bad_reference=True)
    rebind_seal()
    reject(create, "variant receipt is incomplete")
    reject(validate, "variant receipt is incomplete")
    install_pair(new_production, new_variant)
    value = load(paths["desktop-join"])
    value["artifact"]["ios"]["artifactReceiptSha256"] = "0" * 64
    write(paths["desktop-join"], value)
    rebind_seal()
    reject(create, "desktop/mobile join")
    reject(validate, "desktop/mobile join")
    install_pair(new_production, new_variant)
    rebind_seal()
    value = load(seal)
    value["desktopJoinIosProductionReceiptSha256"] = "0" * 64
    write(seal, value)
    reject(validate, "sealed desktop iOS receipt pair differs")

    def install_original_pair(p, v):
        write(paths["mobile"], p)
        v = copy.deepcopy(v)
        v["productionArtifactReceiptSha256"] = sha(paths["mobile"])
        write(paths["variant"], v)
        receipt = json.loads(original_bytes["mobile-join"])
        receipt["artifact"]["ios"]["productionArtifactReceiptSha256"] = sha(paths["mobile"])
        receipt["artifact"]["ios"]["artifactReceiptSha256"] = sha(paths["variant"])
        write(paths["mobile-join"], receipt)
        sealed.write_bytes(paths["mobile"].read_bytes())

    # Both sides have the same malformed shape; all exact receipt references
    # are rebound. Only the allowlisted leaf's shape rejects these fixtures.
    for target in ("production", "variant"):
        for field in ("identityReadAt", "identityReadbackSha256"):
            for malformed in ({}, []):
                old_p, old_v = copy.deepcopy(production), copy.deepcopy(variant)
                new_p, new_v = copy.deepcopy(new_production), copy.deepcopy(new_variant)
                for receipt in ((old_p, new_p) if target == "production" else (old_v, new_v)):
                    receipt["selectedPhysicalDevice"][field] = copy.deepcopy(malformed)
                install_original_pair(old_p, old_v)
                install_pair(new_p, new_v)
                rebind_seal()
                pattern = "iOS " + ("production receipts" if target == "production" else "join variant receipts")
                reject(create, pattern)
                reject(validate, pattern)
        # Identical key presence on both sides, with unequal literal-key
        # values, must not receive the genuine nested observation exemption.
        old_p, old_v = copy.deepcopy(production), copy.deepcopy(variant)
        new_p, new_v = copy.deepcopy(new_production), copy.deepcopy(new_variant)
        left, right = (old_p, new_p) if target == "production" else (old_v, new_v)
        left["selectedPhysicalDevice.identityReadAt"] = "original"
        right["selectedPhysicalDevice.identityReadAt"] = "changed"
        install_original_pair(old_p, old_v)
        install_pair(new_p, new_v)
        rebind_seal()
        pattern = "iOS " + ("production receipts" if target == "production" else "join variant receipts")
        reject(create, pattern)
        reject(validate, pattern)
    for name in ("mobile", "variant", "mobile-join"):
        paths[name].write_bytes(original_bytes[name])
    for name, original in original_bytes.items():
        if name != "desktop-join":
            assert paths[name].read_bytes() == original
    paths["desktop-join"].write_bytes(original_bytes["desktop-join"])
    create()
    validate()

    # Both physical Android receipts must be supplied and authenticated when
    # packaging metadata changed around the same tested APK.
    metadata = ("aabSha256", "apkPathSha256", "bundleReceiptSha256",
                "hostedAdmissionCanonicalSha256", "hostedAdmissionReceiptSha256")
    mobile_android_path = root / "mobile-android.json"
    desktop_android_path = root / "desktop-android.json"
    android = copy.deepcopy(load(paths["mobile-join"])["artifact"]["android"])
    android.pop("artifactReceiptSha256")
    android.update({name: "1" * 64 for name in metadata})
    android["receiptSchema"] = 2
    android["debuggable"] = False
    current_android = {**android, **{name: "2" * 64 for name in metadata}}
    android_args = ["--mobile-join-android-receipt", str(mobile_android_path),
                    "--desktop-join-android-receipt", str(desktop_android_path)]

    def install_android_pair(previous, current):
        write(mobile_android_path, previous)
        write(desktop_android_path, current)
        for name, receipt_path in (("mobile-join", mobile_android_path),
                                   ("desktop-join", desktop_android_path)):
            value = json.loads(original_bytes[name])
            value["artifact"]["android"]["artifactReceiptSha256"] = sha(receipt_path)
            write(paths[name], value)

    install_android_pair(android, current_android)
    create(android_args)
    validate(android_args)
    android_seal = load(seal)
    assert android_seal["mobileJoinAndroidArtifactReceiptSha256"] == sha(mobile_android_path)
    assert android_seal["desktopJoinAndroidArtifactReceiptSha256"] == sha(desktop_android_path)

    def reject_android(arguments=android_args):
        for operation in (create, validate):
            try:
                operation(arguments)
            except ValueError:
                pass
            else:
                raise AssertionError("invalid Android receipt pair was accepted")

    reject_android(())
    reject_android(android_args[:2])
    reject_android(android_args[2:])
    mutations = [
        lambda v: v.update(apkSha256="f" * 64),
        lambda v: v.update(appGitSha="f" * 40),
        lambda v: v.update(signerCertificateSha256="f" * 64),
        lambda v: v.update(debuggable=0),
        lambda v: v.pop("package"),
        lambda v: v.update(unknown=True),
        lambda v: v.update(aabSha256="invalid"),
        lambda v: v.update(aabSha256=["2" * 64]),
        lambda v: v.pop("hostedAdmissionReceiptSha256"),
    ]
    for mutate in mutations:
        bad = copy.deepcopy(current_android)
        mutate(bad)
        install_android_pair(android, bad)
        reject_android()
    # Validate both metadata sets, even when their malformed values agree.
    malformed = {**android, "aabSha256": ["1" * 64]}
    install_android_pair(malformed, malformed)
    reject_android()
    install_android_pair(android, current_android)
    write(seal, {**android_seal, "desktopJoinAndroidArtifactReceiptSha256": "0" * 64})
    try:
        validate(android_args)
    except ValueError:
        pass
    else:
        raise AssertionError("stale sealed Android pair was accepted")
    # A mutually changed pair cannot contradict the joins' actual APK identity.
    changed = {**android, "apkSha256": "f" * 64}
    install_android_pair(changed, changed)
    reject_android()
    install_android_pair(android, current_android)
    value = load(paths["desktop-join"])
    value["artifact"]["android"]["artifactReceiptSha256"] = "0" * 64
    write(paths["desktop-join"], value)
    reject_android()

print("iOS receipt pairs: legacy/iOS cases and Android packaging-only pair cases passed")
