#!/usr/bin/env python3
"""Bind hosted macOS compilation to locally signed bytes; never build or sign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile

from apple_hosted_admission import (
    APP, FIPS, PRODUCER, REALIZED_LOCK, REPOSITORY, canonical_digest, digest,
    load, require, verified_inputs, write, canonicalize_stripped_linkedit,
)
from mobile_release_artifact_receipt import tree_sha256

ARTIFACT_TYPE = "signed hosted macOS app admission"
NORMALIZATION = "codesign-remove-signature-linkedit-allocation-and-share-group-v2"
STAPLE_TICKET = "Contents/CodeResources"
HOST_RESERVE = 20 * 1024**3
RAM_RESERVE = 128 * 1024**2
SCRATCH_ADMISSION_ENV = "NVPN_MACOS_ADMISSION_SCRATCH_ADMISSION"
COMMITTED_LOCK = "1d72aac7e6e5355dc5c903a7f39ae376172739e1c6cd954cadcc88bec33bfb79"
RECIPE_SHA = "5f32a66a91b6788047d829b90044df7af24428f93a055363b8d35926196379ec"
RELEASE_COMMON_SHA = "25445a5829bef66b3fa25d934498964e54cc3762cf5ef74026dd07c29e1fffe7"
UNSIGNED_GROUP = "group.fi.siriusbusiness.nvpn.shared"
UNSIGNED_APP = "macos/.build/ReleaseDerivedData/Build/Products/Release/Nostr VPN.app"
AUTHENTICATION = {
    "repository": REPOSITORY, "workflow": ".github/workflows/apple-release-inputs.yml",
    "producerCommit": PRODUCER, "runId": "41902045004", "jobId": 126826755088,
    "jobName": "inputs (macos)", "jobConclusion": "success",
    "artifactId": 13361231905, "artifactBytes": 99406197,
    "artifactName": "apple-release-inputs-macos-" + APP["commit"],
    "artifactSha256": "b22a6e90130e9b9f7177326c14bbc708cc2b0da6fa10bda6bfe85de0cd132b89",
}
RECIPES = [
    ["scripts/macos-build", "macos-xcframework"],
    ["scripts/macos-build", "macos-xcodeproj"],
    ["xcodebuild", "-jobs", "1", "-project", "macos/NostrVpnMac.xcodeproj",
     "-scheme", "NostrVpnMac", "-configuration", "Release", "-derivedDataPath",
     "macos/.build/ReleaseDerivedData", "-destination", "generic/platform=macOS",
     "ARCHS=arm64", "ONLY_ACTIVE_ARCH=NO", "SKIP_INSTALL=NO",
     "SWIFT_COMPILATION_MODE=singlefile", "SWIFT_ENABLE_BATCH_MODE=NO",
     "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO", "CODE_SIGN_IDENTITY=",
     "DEVELOPMENT_TEAM=", "OTHER_LDFLAGS=$(inherited) -Wl,-S", "build"],
]
EXECUTABLES = {
    "appExecutableSha256": "Contents/MacOS/Nostr VPN",
    "cliExecutableSha256": "Contents/Resources/nvpn",
    "shareFilesExecutableSha256": "Contents/PlugIns/ShareFiles.appex/Contents/MacOS/ShareFiles",
}
GROUP_PLISTS = ("Contents/Info.plist", "Contents/PlugIns/ShareFiles.appex/Contents/Info.plist")
SIGNATURE_DIRS = ("Contents/_CodeSignature", "Contents/PlugIns/ShareFiles.appex/Contents/_CodeSignature")
BUILD_CONTRACT = {
    "application": APP, "fips": FIPS, "rustTarget": "aarch64-apple-darwin",
    "rustProfile": "release", "rustDefaultFeatures": True,
    "committedLockSha256": COMMITTED_LOCK, "realizedLockSha256": REALIZED_LOCK,
    "canonicalRecipeSha256": RECIPE_SHA, "releaseCommonSha256": RELEASE_COMMON_SHA,
    "producerCommit": PRODUCER, "recipes": RECIPES,
}


def validate_build_proof(proof):
    authentication = proof["authentication"]
    require(all(authentication.get(key) == value for key, value in AUTHENTICATION.items()),
            "macOS hosted job/artifact is not the admitted immutable producer")
    require(re.fullmatch(r"[1-9][0-9]*", authentication.get("runAttempt", "")),
            "macOS hosted attempt is missing")
    receipt = proof["producerReceipt"]
    expected = {"app": APP, "fips": FIPS, "committedLockSha256": COMMITTED_LOCK,
                "realizedLockSha256": REALIZED_LOCK, "recipes": RECIPES}
    require(all(receipt.get(key) == value for key, value in expected.items()),
            "macOS hosted source/lock/target/recipe differs")


def comparison_scratch(copy_bytes):
    """Use the host reserve, or a separately admitted, identified RAM volume."""
    growth = 2 * copy_bytes + 1024**2  # copy plus possible codesign rewrite and metadata
    contract_path = os.environ.get(SCRATCH_ADMISSION_ENV)
    if not contract_path:
        root = pathlib.Path(tempfile.gettempdir())
        reserve = HOST_RESERVE
    else:
        contract = load(pathlib.Path(contract_path))
        require(contract.get("receiptSchema") == 1 and contract.get("storageKind") == "ram-disk",
                "comparison scratch needs an explicit RAM-volume admission")
        root = pathlib.Path(contract["directory"])
        mount = pathlib.Path(contract["mountPoint"])
        require(root.is_absolute() and root.is_dir() and root.resolve() == root
                and mount.is_absolute() and mount.resolve() == mount
                and root.is_relative_to(mount), "comparison scratch path differs from admission")
        info = plistlib.loads(subprocess.check_output(["diskutil", "info", "-plist", str(mount)]))
        require(info.get("VolumeUUID") == contract.get("volumeUuid")
                and isinstance(contract.get("volumeUuid"), str) and bool(contract["volumeUuid"])
                and info.get("MountPoint") == str(mount)
                and root.stat().st_dev == mount.stat().st_dev
                and root.stat().st_dev != pathlib.Path.home().stat().st_dev,
                "comparison scratch volume identity differs from admission")
        images = plistlib.loads(subprocess.check_output(["hdiutil", "info", "-plist"]))
        require(any(re.fullmatch(r"ram://[1-9][0-9]*", image.get("image-path", ""))
                    and any(entity.get("dev-entry") == info.get("DeviceNode")
                            and entity.get("mount-point") == str(mount)
                            for entity in image.get("system-entities", []))
                    for image in images.get("images", [])),
                "comparison scratch is not the admitted RAM device")
        reserve = contract.get("reserveBytes")
        maximum_growth = contract.get("maximumGrowthBytes")
        require(type(reserve) is int and reserve >= RAM_RESERVE
                and type(maximum_growth) is int and growth <= maximum_growth,
                "comparison scratch reserve or growth budget is insufficient")
    require(shutil.disk_usage(root).free >= reserve + growth,
            "signature comparison would breach the admitted scratch reserve")
    return root


def normalized_executable(path):
    """Remove only the signature using Apple's tool, on a bounded temporary copy."""
    temporary_root = comparison_scratch(path.stat().st_size)
    with tempfile.TemporaryDirectory(prefix="nvpn-macos-signature-", dir=temporary_root) as temporary:
        copy = pathlib.Path(temporary) / "executable"
        shutil.copy2(path, copy)
        subprocess.run(["codesign", "--remove-signature", str(copy)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        canonicalize_stripped_linkedit(path, copy)
        return digest(copy)


def content_identity(app, expected_group, *, stapled=False):
    """Bind every non-signature byte/mode, allowing only the exact app-group field."""
    require(app.is_dir() and not app.is_symlink(), "macOS app directory is missing or a link")
    entries = []
    executable_paths = set(EXECUTABLES.values())
    seen = set()
    for path in sorted(app.rglob("*")):
        relative = path.relative_to(app).as_posix()
        require(not path.is_symlink(), "macOS admission does not accept symlinks")
        if path.is_dir():
            continue
        require(path.is_file(), "unsupported macOS bundle entry")
        if stapled and relative == STAPLE_TICKET:
            continue
        if any(relative.startswith(directory + "/") for directory in SIGNATURE_DIRS):
            continue
        seen.add(relative)
        mode = stat.S_IMODE(path.stat().st_mode)
        if relative in executable_paths:
            sha = normalized_executable(path)
        elif relative in GROUP_PLISTS:
            info = plistlib.loads(path.read_bytes())
            require(isinstance(info, dict) and info.get("NVPNShareAppGroup") == expected_group,
                    "macOS Info.plist has the wrong signing app group")
            info["NVPNShareAppGroup"] = "<admitted-signing-app-group>"
            sha = hashlib.sha256(plistlib.dumps(info, fmt=plistlib.FMT_BINARY, sort_keys=True)).hexdigest()
        else:
            sha = digest(path)
        entries.append({"path": relative, "mode": mode, "sha256": sha})
    require(executable_paths.union(GROUP_PLISTS) <= seen, "macOS app/CLI/ShareFiles payload is incomplete")
    return {"files": entries, "manifestSha256": canonical_digest(entries)}


def signed_identity(app):
    return {"appBundleTreeSha256": tree_sha256(app),
            **{key: digest(app / relative) for key, relative in EXECUTABLES.items()}}


def unstapled_tree_sha256(app):
    """Match tree_sha256 exactly, omitting only Apple's top-level staple ticket."""
    entries = []
    for current, directories, files in os.walk(app, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories + files:
            require(not (pathlib.Path(current) / name).is_symlink(), "stapled app contains a link")
        for name in files:
            path = pathlib.Path(current) / name
            relative = path.relative_to(app).as_posix()
            require(path.is_file(), "unsupported stapled app entry")
            if relative != STAPLE_TICKET:
                metadata = path.stat()
                entries.append({"mode": stat.S_IMODE(metadata.st_mode), "path": relative,
                                "sha256": digest(path), "size": metadata.st_size, "type": "file"})
    return canonical_digest(entries)


def inspect_signing(app, expected):
    from macos_release_join_artifact import inspect_signature, verify_signature
    for label, path in (("macOS app", app), ("macOS CLI", app / EXECUTABLES["cliExecutableSha256"]),
                        ("macOS ShareFiles", app / "Contents/PlugIns/ShareFiles.appex")):
        signature = inspect_signature(path, deep=path == app)
        verify_signature(signature, expected_team=expected["team"],
                         expected_identity=expected["certificateSha1"],
                         expected_signer=expected["certificateSha256"], label=label)
    group = expected["team"] + ".fi.siriusbusiness.nvpn.shared"
    for bundle in (app, app / "Contents/PlugIns/ShareFiles.appex"):
        entitlements = plistlib.loads(subprocess.check_output(
            ["codesign", "-d", "--entitlements", ":-", str(bundle)], stderr=subprocess.PIPE))
        require(entitlements.get("com.apple.security.application-groups") == [group],
                "macOS signed entitlements disagree with the admitted app group")
    return group


def assert_current_app(admission, app, *, allow_stapled=False):
    require(admission.get("normalization") == NORMALIZATION, "unknown macOS signing normalization")
    require(all(entry["path"] != STAPLE_TICKET for entry in admission["contentIdentity"]["files"]),
            "macOS admission must precede stapling")
    ticket = app / STAPLE_TICKET
    stapled = allow_stapled and ticket.exists()
    identity = signed_identity(app)
    if stapled:
        require(ticket.is_file() and not ticket.is_symlink(), "invalid macOS staple ticket entry")
        # Apple's stapler(1) reserves Contents/CodeResources, separately from the
        # signed Contents/_CodeSignature/CodeResources, and validates its ticket.
        subprocess.run(["xcrun", "stapler", "validate", str(app)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        identity["appBundleTreeSha256"] = unstapled_tree_sha256(app)
    require(identity == admission["appIdentity"],
            "current signed macOS payload differs from admitted bytes")
    require(content_identity(app, admission["signedAppGroup"], stapled=stapled) == admission["contentIdentity"],
            "current macOS content differs from hosted compilation")
    return admission


def validate_admission(companion, app, *, allow_stapled=False):
    admission = load(companion)
    require(admission.get("receiptSchema") == 1 and admission.get("artifactType") == ARTIFACT_TYPE,
            "wrong macOS hosted admission schema")
    directory = admission.get("inputDirectory")
    require(isinstance(directory, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", directory),
            "macOS admission input directory must be a portable sibling name")
    root = companion.parent / directory
    require(root.resolve().parent == companion.parent.resolve(), "macOS input directory escapes its package")
    proof = verified_inputs(root, "macos")
    validate_build_proof(proof)
    require(admission["authentication"] == proof["authentication"]
            and admission["inputProofSha256"] == digest(root / "hosted-inputs.json")
            and admission["producerReceiptSha256"] == proof["producerReceiptSha256"]
            and admission["buildContract"] == BUILD_CONTRACT,
            "macOS hosted build evidence changed")
    unsigned = root / "unsigned" / UNSIGNED_APP
    require(content_identity(unsigned, UNSIGNED_GROUP) == admission["contentIdentity"],
            "macOS admission does not describe original hosted bytes")
    assert_current_app(admission, app, allow_stapled=allow_stapled)
    require(inspect_signing(app, admission["signing"]) == admission["signedAppGroup"],
            "macOS admission signing group changed")
    return admission


def receipt_fields(companion, admission):
    return {"receiptSchema": 2, "builtOnHost": False, "builtOnTestVm": False,
            "buildOrigin": "github-actions", "signedOnHost": True,
            "hostedAdmissionReceiptSha256": digest(companion),
            "hostedAdmissionCanonicalSha256": canonical_digest(admission),
            "hostedAdmission": admission}


def validate_receipt_binding(receipt, companion, admission):
    for key, value in receipt_fields(companion, admission).items():
        require(receipt.get(key) == value, "macOS hosted receipt differs at " + key)
    for key, value in {"appGitSha": APP["commit"], "appGitTree": APP["tree"],
                       "fipsGitSha": FIPS["commit"], "fipsGitTree": FIPS["tree"],
                       "fipsCoreVersion": "0.4.117"}.items():
        require(receipt.get(key) == value, "macOS receipt source differs at " + key)
    for key, value in admission["appIdentity"].items():
        require(receipt.get(key) == value, "macOS receipt payload differs at " + key)
    for key, value in (("signingTeam", "team"), ("signingIdentitySha1", "certificateSha1"),
                       ("signerCertificateSha256", "certificateSha256")):
        require(receipt.get(key) == admission["signing"][value], "macOS signing receipt differs")


def validate_receipt_admission(receipt, companion, app, *, allow_stapled=False):
    hosted_keys = {"hostedAdmission", "hostedAdmissionReceiptSha256",
                   "hostedAdmissionCanonicalSha256", "buildOrigin", "signedOnHost"}
    if receipt.get("receiptSchema") == 1:
        require(not hosted_keys.intersection(receipt) and not companion.exists(),
                "hosted macOS evidence cannot be downgraded to a local receipt")
        require(receipt.get("builtOnHost") is True and receipt.get("builtOnTestVm") is False,
                "legacy macOS receipt does not prove local compilation")
        return None
    require(receipt.get("receiptSchema") == 2, "unsupported macOS artifact schema")
    admission = validate_admission(companion, app, allow_stapled=allow_stapled)
    validate_receipt_binding(receipt, companion, admission)
    return admission


def admit(args):
    output = pathlib.Path(args.output).resolve()
    require(not output.exists(), "macOS admission output must be fresh")
    inputs = pathlib.Path(args.inputs).resolve()
    root = inputs.parent
    require(inputs.name == "hosted-inputs.json" and root.parent == output.parent
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", root.name),
            "retain hosted inputs beside the portable macOS admission")
    proof = verified_inputs(root, "macos")
    validate_build_proof(proof)
    for root_path, identity in ((args.source_root, APP), (args.fips_root, FIPS)):
        observed = subprocess.check_output(["git", "-C", root_path, "rev-parse", identity["commit"] + "^{tree}"], text=True).strip()
        require(observed == identity["tree"], "macOS validation source tree differs")
    for relative, expected in (("scripts/macos-build", RECIPE_SHA), ("Cargo.lock", COMMITTED_LOCK),
                               ("scripts/release_common.sh", RELEASE_COMMON_SHA)):
        data = subprocess.check_output(["git", "-C", args.source_root, "show", APP["commit"] + ":" + relative])
        require(hashlib.sha256(data).hexdigest() == expected, "macOS frozen recipe differs")
    app = pathlib.Path(args.app).resolve()
    require(not (app / STAPLE_TICKET).exists(), "admit the signed macOS app before stapling")
    signing = {"team": args.expected_team, "certificateSha1": args.expected_identity_sha1,
               "certificateSha256": args.expected_signer_sha256}
    require(re.fullmatch(r"[A-Z0-9]{10}", signing["team"])
            and re.fullmatch(r"[0-9a-f]{40}", signing["certificateSha1"])
            and re.fullmatch(r"[0-9a-f]{64}", signing["certificateSha256"]), "invalid macOS signing pins")
    group = inspect_signing(app, signing)
    unsigned_identity = content_identity(root / "unsigned" / UNSIGNED_APP, UNSIGNED_GROUP)
    require(content_identity(app, group) == unsigned_identity,
            "signed macOS app differs beyond signatures and the exact app-group field")
    admission = {"receiptSchema": 1, "artifactType": ARTIFACT_TYPE,
                 "inputDirectory": root.name,
                 "normalization": NORMALIZATION, "authentication": proof["authentication"],
                 "inputProofSha256": digest(root / "hosted-inputs.json"),
                 "producerReceiptSha256": proof["producerReceiptSha256"],
                 "buildContract": BUILD_CONTRACT, "contentIdentity": unsigned_identity,
                 "appIdentity": signed_identity(app), "signing": signing, "signedAppGroup": group}
    write(output, admission)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inputs", "output", "app", "source-root", "fips-root", "expected-team",
                 "expected-identity-sha1", "expected-signer-sha256"):
        parser.add_argument("--" + name, required=True)
    admit(parser.parse_args())


if __name__ == "__main__":
    main()
