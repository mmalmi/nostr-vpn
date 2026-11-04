#!/usr/bin/env python3
"""Bind hosted Android compilation to local AAB signing and canonical APK derivation."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess

from android_hosted_content import aab_content_identity, apk_runtime_identity, verify_aab_signer
from android_hosted_inputs import (
    APP, FIPS, FIPS_VERSION, COMMITTED_LOCK, REALIZED_LOCK, SCRIPTS, BUNDLETOOL_SHA,
    authenticate_inputs, canonical_digest, digest, load, require, verified_inputs, write,
)

TYPE = "signed hosted Android AAB and derived APK admission"
CONTRACT = "exact-aab-payload-jar-manifest-and-pinned-signer-v1"
def path_digest(path):
    return hashlib.sha256(str(path.resolve()).encode()).hexdigest()


def git(root, *arguments, raw=False):
    output = subprocess.check_output(["git", "-C", str(root), *arguments],
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    return output if raw else output.strip()


def local_validation(source_root, fips_root, metadata_path, realized_lock):
    require(git(source_root, "rev-parse", APP["commit"] + "^{tree}").decode() == APP["tree"],
            "Android validation source object differs")
    require(git(fips_root, "rev-parse", "HEAD").decode() == FIPS["commit"]
            and git(fips_root, "rev-parse", "HEAD^{tree}").decode() == FIPS["tree"]
            and not git(fips_root, "status", "--porcelain", "--untracked-files=all"),
            "Android local FIPS validation checkout is not the exact clean source")
    for path, expected in {**SCRIPTS, "Cargo.lock": COMMITTED_LOCK}.items():
        require(hashlib.sha256(git(source_root, "show", APP["commit"] + ":" + path, raw=True)).hexdigest() == expected,
                "Android canonical validation recipe differs")
    metadata = load(metadata_path)
    expected = {"checkoutHead": FIPS["commit"], "checkoutTree": FIPS["tree"],
        "fipsCoreVersion": FIPS_VERSION, "checkoutPathSha256": path_digest(fips_root),
        "fipsCoreManifestPathSha256": path_digest(fips_root / "crates/fips-core/Cargo.toml"),
        "source": "exact clean local Cargo path dependency"}
    require(all(metadata.get(key) == value for key, value in expected.items()),
            "Android local validation metadata differs from its checkout")
    require(re.fullmatch(r"[0-9a-f]{64}", metadata.get("fipsCorePackageIdSha256", "")),
            "Android local validation lacks its package graph identity")
    require(realized_lock.is_file() and not realized_lock.is_symlink()
            and digest(realized_lock) == REALIZED_LOCK,
            "Android local metadata validation resolved a different locked graph")
    return {"metadata": metadata, "metadataSha256": digest(metadata_path),
            "application": APP, "fips": FIPS, "realizedLockSha256": digest(realized_lock),
            "compilationPerformed": False}


def validate_bundle_receipt(bundle, aab, apk, *, current_paths=False):
    expected = {"schema": 1, "relationship": "universal-apk-derived-from-exact-aab",
        "appGitSha": APP["commit"], "appGitTree": APP["tree"],
        "aabSha256": digest(aab), "apkSha256": digest(apk),
        "bundletoolVersion": "1.18.3", "bundletoolSha256": BUNDLETOOL_SHA}
    require(all(bundle.get(key) == value for key, value in expected.items()),
            "Android APK is not sealed to the exact canonical AAB derivation")
    for name, path in (("aab", aab), ("apk", apk)):
        require(re.fullmatch(r"[0-9a-f]{64}", bundle.get(name + "PathSha256", "")),
                "Android derivation path identity is absent")
        if current_paths:
            require(bundle[name + "PathSha256"] == path_digest(path), "Android derivation paths changed before admission")


def verify_apk_signer(apk, expected_sha256):
    executable = os.environ.get("NVPN_ANDROID_APKSIGNER")
    if not executable:
        sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        require(sdk, "Android APK signature verification needs the qualified SDK")
        paths = sorted((pathlib.Path(sdk) / "build-tools").glob("*/apksigner"),
                       key=lambda path: tuple(int(part) for part in re.findall(r"\d+", path.parent.name)))
        require(paths, "Android apksigner is missing")
        executable = str(paths[-1])
    result = subprocess.run([executable, "verify", "--verbose", "--print-certs", str(apk)],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    signers = re.findall(r"Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]{64})", result.stdout)
    require(len(signers) == 1 and signers[0].lower() == expected_sha256, "Android APK signer differs")


def sibling(companion, name):
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name),
            "Android admission sibling must have a portable leaf name")
    path = companion.parent / name
    require(not path.is_symlink() and path.resolve().parent == companion.parent.resolve(),
            "Android admission sibling escapes its package")
    return path


def observe(companion, admission, aab, apk, bundle_path, source_root, fips_root):
    root = sibling(companion, admission["inputDirectory"])
    proof = verified_inputs(root)
    local = local_validation(source_root, fips_root, sibling(companion, admission["localValidationFile"]),
                             sibling(companion, admission["localRealizedLockFile"]))
    unsigned = root / "payload/unsigned/app-release.aab"
    content = aab_content_identity(unsigned, aab)
    runtime = apk_runtime_identity(aab, apk)
    signer = admission["signerCertificateSha256"]
    verify_aab_signer(aab, content["signatureEntries"], signer)
    verify_apk_signer(apk, signer)
    bundle = load(bundle_path)
    validate_bundle_receipt(bundle, aab, apk)
    receipt = proof["producerReceipt"]
    return {"authentication": proof["authentication"],
        "inputProofSha256": digest(root / "hosted-inputs.json"),
        "producerReceiptSha256": proof["producerReceiptSha256"],
        "historicalFipsMetadata": proof["historicalFipsMetadata"],
        "historicalFipsMetadataSha256": digest(root / "payload/provenance/fips-linkage.json"),
        "localValidation": local,
        "buildContract": {"application": APP, "fips": FIPS, "canonicalScripts": SCRIPTS,
            "rust": receipt["rust"], "committedLockSha256": COMMITTED_LOCK, "realizedLockSha256": REALIZED_LOCK,
            "inputPinsSha256": digest(root / "payload/provenance/inputs.json"),
            "recipeSha256": digest(root / "payload/provenance/build.sh"),
            "environmentSha256": digest(root / "payload/provenance/build-environment.json")},
        "aabSha256": digest(aab), "apkSha256": digest(apk),
        "signedAabContent": content, "apkRuntimeContent": runtime,
        "bundleReceiptSha256": digest(bundle_path), "derivation": bundle}


def validate_admission(companion, aab, apk, bundle_path, source_root, fips_root, signer):
    admission = load(companion)
    require(admission.get("receiptSchema") == 1 and admission.get("artifactType") == TYPE
            and admission.get("contentContract") == CONTRACT
            and admission.get("signerCertificateSha256") == signer,
            "Android hosted admission schema or signer differs")
    observed = observe(companion, admission, aab, apk, bundle_path, source_root, fips_root)
    require(all(admission.get(key) == value for key, value in observed.items()),
            "Android signed payload, historical evidence, or local validation changed")
    return admission


def receipt_fields(companion, admission):
    return {"buildOrigin": "github-actions", "builtOnHost": False, "signedOnHost": True,
        "hostedAdmissionReceiptSha256": digest(companion),
        "hostedAdmissionCanonicalSha256": canonical_digest(admission),
        "fipsCheckoutPathSha256": admission["historicalFipsMetadata"]["checkoutPathSha256"],
        "localFipsValidationCheckoutPathSha256": admission["localValidation"]["metadata"]["checkoutPathSha256"],
        "fipsDependenciesBuildOrigin": "github-actions"}


def validate_physical_receipt(receipt, companion, aab, apk, bundle_path, metadata, source_root, fips_root, signer):
    admission = validate_admission(companion, aab, apk, bundle_path, source_root, fips_root, signer)
    require(load(metadata) == admission["historicalFipsMetadata"]
            and digest(metadata) == admission["historicalFipsMetadataSha256"],
            "Android physical receipt retagged hosted FIPS metadata")
    require(all(receipt.get(key) == value for key, value in receipt_fields(companion, admission).items()),
            "Android physical receipt lacks its exact hosted admission")
    return admission


def admit(args):
    companion = pathlib.Path(args.admission).resolve()
    inputs = pathlib.Path(args.inputs).resolve()
    local_metadata = pathlib.Path(args.local_fips_metadata).resolve()
    local_lock = pathlib.Path(args.local_realized_lock).resolve()
    require(inputs.name == "hosted-inputs.json" and inputs.parent.parent == companion.parent,
            "retain Android hosted inputs beside the admission")
    require(local_metadata.parent == local_lock.parent == companion.parent,
            "retain separate local FIPS validation and realized lock beside the admission")
    admission = {"receiptSchema": 1, "artifactType": TYPE, "contentContract": CONTRACT,
        "inputDirectory": inputs.parent.name, "localValidationFile": local_metadata.name,
        "localRealizedLockFile": local_lock.name,
        "signerCertificateSha256": args.signer_sha}
    aab, apk, bundle = map(pathlib.Path, (args.aab, args.apk, args.bundle_receipt))
    validate_bundle_receipt(load(bundle), aab, apk, current_paths=True)
    admission.update(observe(companion, admission, aab, apk, bundle,
                             pathlib.Path(args.app_root), pathlib.Path(args.fips_root)))
    write(companion, admission)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    authenticate = commands.add_parser("authenticate-inputs")
    authenticate.add_argument("--root", required=True)
    for name in ("admit", "verify"):
        command = commands.add_parser(name)
        for option in ("admission", "aab", "apk", "bundle-receipt", "app-root", "fips-root", "signer-sha"):
            command.add_argument("--" + option, required=True)
        if name == "admit":
            command.add_argument("--inputs", required=True)
            command.add_argument("--local-fips-metadata", required=True)
            command.add_argument("--local-realized-lock", required=True)
        else:
            command.add_argument("--fips-metadata", required=True)
    args = parser.parse_args()
    if args.command == "authenticate-inputs":
        authenticate_inputs(pathlib.Path(args.root))
    elif args.command == "admit":
        admit(args)
    else:
        companion = pathlib.Path(args.admission)
        admission = validate_admission(companion, pathlib.Path(args.aab), pathlib.Path(args.apk),
            pathlib.Path(args.bundle_receipt), pathlib.Path(args.app_root), pathlib.Path(args.fips_root), args.signer_sha)
        require(load(pathlib.Path(args.fips_metadata)) == admission["historicalFipsMetadata"]
                and digest(pathlib.Path(args.fips_metadata)) == admission["historicalFipsMetadataSha256"],
                "Android original hosted FIPS metadata changed")
        print(json.dumps(receipt_fields(companion, admission), sort_keys=True))


if __name__ == "__main__":
    main()
