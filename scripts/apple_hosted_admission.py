#!/usr/bin/env python3
"""Admit immutable hosted Apple build inputs; never compile or sign them."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import tarfile
import zipfile


REPOSITORY = "mmalmi/nostr-vpn"
PRODUCER = "92ab2ceb349c1c0d46f68a591493fbbe9f357144"
PRODUCERS = {"ios": PRODUCER, "macos": PRODUCER,
             "ios-join": "5e9d464e34d9f312d5ef2df6c2757e51df2cde8b",
             "macos-support": "b940ed359d394e673f287ff5c807b1afac5864e7"}
APP = {"commit": "52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4",
       "tree": "2f722bd2e0f34e7b71cae665cce74c3080c99661"}
FIPS = {"commit": "d0b18f2d1b2e97d42fa8460a0c70a8dffeaa2552",
        "tree": "08ceced056b8592a2b2c840c4c276bf01cf28c85"}
REALIZED_LOCK = "41067773c75d291993622ac7d0a66ac77e3ce050ff6b9a646466a413f5cb065a"
IOS_SIGNING_NORMALIZATION = "codesign-remove-signature-linkedit-allocation-v1"
IOS_EXECUTABLES = {
    "appNormalizedExecutableSha256": "Nostr VPN",
    "packetTunnelNormalizedExecutableSha256": "PlugIns/Nostr VPN Tunnel.appex/Nostr VPN Tunnel",
    "shareFilesNormalizedExecutableSha256": "PlugIns/ShareFiles.appex/ShareFiles",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def macho_linkedit(path):
    """Read only the bounded load commands of this producer's thin ARM64 files."""
    length = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(32)
        require(len(header) == 32, "truncated Mach-O header")
        magic, cpu, _subtype, _kind, count, size, _flags, _reserved = struct.unpack("<8I", header)
        require(magic == 0xFEEDFACF and cpu == 0x0100000C
                and 0 < count <= 4096 and 0 < size <= 1024**2 and 32 + size <= length,
                "expected bounded thin ARM64 load commands")
        commands = stream.read(size)
    offset = 0
    linkedit = None
    signature = None
    for _ in range(count):
        require(offset + 8 <= size, "truncated Mach-O load command")
        command, command_size = struct.unpack_from("<II", commands, offset)
        require(command_size >= 8 and command_size % 8 == 0 and offset + command_size <= size,
                "invalid Mach-O load command size")
        if command == 0x19:
            require(command_size >= 72, "truncated Mach-O segment")
            if commands[offset + 8:offset + 24].rstrip(b"\0") == b"__LINKEDIT":
                require(linkedit is None and command_size == 72, "ambiguous LINKEDIT segment")
                address, allocation, file_offset, file_size = struct.unpack_from("<4Q", commands, offset + 24)
                linkedit = {"offset": 32 + offset, "address": address, "allocation": allocation,
                            "fileOffset": file_offset, "fileSize": file_size}
        if command == 0x1D:
            require(signature is None and command_size == 16, "ambiguous code signature command")
            signature = struct.unpack_from("<2I", commands, offset + 8)
        offset += command_size
    require(offset == size and linkedit is not None
            and linkedit["fileOffset"] >= 32 + size and linkedit["fileSize"] > 0
            and linkedit["fileOffset"] + linkedit["fileSize"] == length,
            "LINKEDIT must be the final complete file segment")
    return linkedit, signature


def canonicalize_stripped_linkedit(original, stripped):
    """Normalize only the signature-dependent allocation left by codesign.

    codesign truncates signature bytes and adjusts LINKEDIT filesize, but keeps
    its former virtual allocation. Require that allocation to be derived from
    the original signed segment before replacing the single eight-byte field.
    """
    raw, signature = macho_linkedit(original)
    current, remaining_signature = macho_linkedit(stripped)
    round_page = lambda size: (size + 16383) // 16384 * 16384
    require(signature is not None and signature[1] > 0 and signature[0] % 16 == 0
            and signature[0] >= raw["fileOffset"]
            and sum(signature) == original.stat().st_size
            and raw["allocation"] == round_page(raw["fileSize"]),
            "original signature allocation is not derived from its exact trailing signature")
    require(remaining_signature is None
            and all(current[key] == raw[key] for key in ("offset", "address", "fileOffset", "allocation"))
            and current["fileOffset"] + current["fileSize"] <= signature[0],
            "signature removal changed unexpected LINKEDIT layout")
    with stripped.open("r+b") as stream:
        stream.seek(current["offset"] + 32)
        stream.write(struct.pack("<Q", round_page(current["fileSize"])))


def load(path):
    return json.loads(pathlib.Path(path).read_text())


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def relative_path(name):
    value = pathlib.PurePosixPath(name)
    require(name and not value.is_absolute() and ".." not in value.parts
            and "\\" not in name and str(value) == name.rstrip("/"),
            "archive contains a noncanonical or escaping path")
    return value


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path], text=True))


def authenticate_run(run, artifact, job, selected, run_id):
    producer = PRODUCERS[selected]
    require(run.get("id") == run_id and run.get("head_sha") == producer
            and run.get("repository", {}).get("full_name") == REPOSITORY
            and run.get("path") == ".github/workflows/apple-release-inputs.yml",
            "hosted workflow is not the reviewed producer")
    require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0,
            "hosted attempt is missing")
    require(job.get("run_id") == run_id and job.get("run_attempt") == run["run_attempt"]
            and job.get("head_sha") == producer and job.get("name") == f"inputs ({selected})"
            and job.get("status") == "completed" and job.get("conclusion") == "success",
            "hosted platform job did not succeed on the reviewed attempt")
    require(artifact.get("name") == f"apple-release-inputs-{selected}-{APP['commit']}"
            and artifact.get("expired") is False
            and artifact.get("workflow_run", {}).get("id") == run_id
            and artifact.get("workflow_run", {}).get("head_sha") == producer,
            "service artifact belongs to a different source/run")
    require(isinstance(artifact.get("digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]) is not None,
            "GitHub did not provide an artifact digest")
    return {"repository": REPOSITORY, "workflow": run["path"],
            "producerCommit": producer, "runId": str(run_id),
            "runAttempt": str(run["run_attempt"]), "jobConclusion": "success",
            "jobId": job["id"], "jobName": job["name"],
            "artifactId": artifact["id"], "artifactName": artifact["name"],
            "artifactBytes": artifact["size_in_bytes"],
            "artifactSha256": artifact["digest"].removeprefix("sha256:")}


def checked_zip(archive, destination, max_bytes):
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
        names = [entry.filename for entry in entries]
        require(len(names) == len(set(names)), "duplicate artifact ZIP entries")
        require(sum(entry.file_size for entry in entries) <= max_bytes,
                "artifact ZIP exceeds admitted expansion budget")
        for entry in entries:
            relative_path(entry.filename)
            require(not stat.S_ISLNK(entry.external_attr >> 16), "artifact ZIP symlink")
        package.extractall(destination)


def checked_tar(archive, destination, files):
    expected = {item["path"]: item for item in files}
    require(len(files) == len(expected), "duplicate producer file entries")
    with tarfile.open(archive, "r:gz") as package:
        entries = package.getmembers()
        names = [entry.name for entry in entries]
        require(len(names) == len(set(names)), "duplicate payload archive entries")
        actual = {}
        for entry in entries:
            relative_path(entry.name)
            require(entry.isdir() or entry.isfile(), "payload contains a link or special file")
            if entry.isfile():
                require(entry.name in expected and entry.size == expected[entry.name]["bytes"],
                        "payload file is missing from producer manifest or has wrong size")
                with package.extractfile(entry) as source:
                    sha = hashlib.sha256()
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        sha.update(block)
                require(sha.hexdigest() == expected[entry.name]["sha256"], "payload file digest differs")
                actual[entry.name] = entry
        require(set(actual) == set(expected), "payload manifest is incomplete")
        # Every member has been checked before writing anything.
        for entry in entries:
            target = destination / entry.name
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(entry) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(entry.mode & 0o777)


def verify_receipt(receipt, authentication, selected):
    expected = {"schema": 1, "app": APP, "fips": FIPS, "producerCommit": PRODUCERS[selected],
                "runId": authentication["runId"], "runAttempt": authentication["runAttempt"],
                "platform": selected, "configuration": "Release",
                "realizedLockSha256": REALIZED_LOCK,
                "archive": selected + "-unsigned-release.tar.gz",
                "xcode": "Xcode 26.6\nBuild version 17F113", "xcodegen": "Version: 2.45.4",
                "sdks": {"iphoneos": "26.5", "iphonesimulator": "26.5", "macosx": "26.5"},
                "distributionSigned": False, "signingIdentityProvided": False,
                "runtimeTestsExecuted": False, "releaseAccepted": False}
    for key, value in expected.items():
        require(receipt.get(key) == value, "hosted receipt differs at " + key)
    if selected == "ios-join":
        require(receipt.get("testOnlyJoinVariant") is True
                and receipt.get("joinTestingCompilationCondition") == "NVPN_RELEASE_JOIN_TESTING"
                and receipt.get("fixtureInfo") == {"CFBundleDisplayName": "Nostr VPN Test Files",
                    "UIFileSharingEnabled": True, "LSSupportsOpeningDocumentsInPlace": True}
                and "OTHER_SWIFT_FLAGS=$(inherited) -DNVPN_RELEASE_JOIN_TESTING" in receipt["recipes"][-1]
                and receipt["recipes"][-1][-1] == "build-for-testing",
                "hosted join variant lacks its separate compilation contract")
    if selected == "macos-support":
        require(receipt.get("recipes") == [["scripts/macos-build", "macos-gate-support"],
            ["xcrun", "swiftc", "-O", "-framework", "AppKit", "-framework", "ApplicationServices",
             "-framework", "Foundation", "-o", "macos/.build/hosted-gate-support/drivers/macos-exit-dns-ax",
             "scripts/macos-exit-dns-ax.swift"]],
                "hosted support inputs used a different canonical recipe")
        require({entry["path"] for entry in receipt["files"]} == {
            "macos/.build/hosted-gate-support/fixtures/desktop_manual_join_e2e_fixture",
            "macos/.build/hosted-gate-support/drivers/desktop-manual-join-ax",
            "macos/.build/hosted-gate-support/drivers/macos-service-toggle-ax",
            "macos/.build/hosted-gate-support/drivers/macos-exit-dns-ax"},
            "hosted support payload differs from the four required tools")
    require(receipt.get("rustc", "").startswith("rustc 1.95.0 (59807616e 2026-04-14)\n"),
            "hosted compiler differs")
    require(receipt.get("runnerImageVersion") and receipt.get("runnerImageOS"),
            "hosted image identity is absent")
    files = receipt.get("files")
    require(isinstance(files, list) and files, "empty hosted payload manifest")
    for item in files:
        relative_path(item["path"])
        require(type(item.get("bytes")) is int and item["bytes"] >= 0
                and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")),
                "invalid hosted payload identity")
    require(sum(item["bytes"] for item in files) == receipt.get("unpackedFileBytes"),
            "hosted expansion size is inconsistent")


def fetch(args):
    root = pathlib.Path(args.destination).resolve()
    require(not root.exists(), "hosted import destination must be fresh")
    selected = args.platform
    run = api(f"repos/{REPOSITORY}/actions/runs/{args.run_id}")
    artifacts = api(f"repos/{REPOSITORY}/actions/runs/{args.run_id}/artifacts?per_page=100")
    matches = [item for item in artifacts["artifacts"] if item["name"] ==
               f"apple-release-inputs-{selected}-{APP['commit']}"]
    require(len(matches) == 1, "expected one exact hosted platform artifact")
    jobs = api(f"repos/{REPOSITORY}/actions/runs/{args.run_id}/attempts/{run['run_attempt']}/jobs")
    matches_jobs = [job for job in jobs["jobs"] if job["name"] == f"inputs ({selected})"]
    require(len(matches_jobs) == 1, "expected one exact platform job")
    authentication = authenticate_run(run, matches[0], matches_jobs[0], selected, args.run_id)
    require(authentication["artifactBytes"] <= args.max_bytes,
            "service artifact exceeds the reserved import budget")
    require(shutil.disk_usage(root.parent).free >= args.max_bytes + args.reserve_bytes,
            "hosted import filesystem lacks its reserved capacity")
    root.mkdir()
    archive = root / "github-artifact.zip"
    with archive.open("xb") as output:
        subprocess.run(["gh", "api", f"repos/{REPOSITORY}/actions/artifacts/"
                        f"{authentication['artifactId']}/zip"], stdout=output, check=True)
    require(archive.stat().st_size == authentication["artifactBytes"]
            and digest(archive) == authentication["artifactSha256"],
            "downloaded service artifact differs from GitHub's digest/size")
    checked_zip(archive, root / "artifact", args.max_bytes - archive.stat().st_size)
    output = root / "artifact/output"
    receipt = load(output / "receipt.json")
    verify_receipt(receipt, authentication, selected)
    payload = output / receipt["archive"]
    require(payload.stat().st_size == receipt["archiveBytes"]
            and digest(payload) == receipt["archiveSha256"], "hosted payload archive differs")
    current_bytes = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    require(current_bytes + receipt["unpackedFileBytes"] <= args.max_bytes,
            "hosted payload exceeds its total reserved import budget")
    checked_tar(payload, root / "unsigned", receipt["files"])
    proof = {"receiptSchema": 1, "artifactType": "verified unsigned hosted Apple inputs",
             "authentication": authentication, "platform": selected,
             "producerReceiptSha256": digest(output / "receipt.json"),
             "producerReceipt": receipt}
    write(root / "hosted-inputs.json", proof)
    print(json.dumps({"platform": selected, "verifiedFiles": len(receipt["files"]),
                      "unsignedBytes": receipt["unpackedFileBytes"],
                      "inputProofSha256": digest(root / "hosted-inputs.json")}))


def verified_inputs(root, selected):
    """Revalidate the retained immutable evidence, without contacting a service."""
    proof = load(root / "hosted-inputs.json")
    require(proof.get("receiptSchema") == 1
            and proof.get("artifactType") == "verified unsigned hosted Apple inputs"
            and proof.get("platform") == selected, "wrong hosted input proof")
    authentication = proof["authentication"]
    require(authentication.get("repository") == REPOSITORY
            and authentication.get("workflow") == ".github/workflows/apple-release-inputs.yml"
            and authentication.get("producerCommit") == PRODUCERS[selected]
            and authentication.get("jobConclusion") == "success"
            and authentication.get("jobName") == f"inputs ({selected})",
            "hosted input proof has no reviewed successful producer")
    package = root / "github-artifact.zip"
    require(package.stat().st_size == authentication["artifactBytes"]
            and digest(package) == authentication["artifactSha256"],
            "retained service artifact changed")
    output = root / "artifact/output"
    receipt = load(output / "receipt.json")
    require(digest(output / "receipt.json") == proof["producerReceiptSha256"]
            and receipt == proof["producerReceipt"], "retained producer receipt changed")
    verify_receipt(receipt, authentication, selected)
    # Tie the extracted receipt and all other evidence back to the service ZIP.
    with zipfile.ZipFile(package) as archive:
        require(archive.read("output/receipt.json") == (output / "receipt.json").read_bytes(),
                "producer receipt does not belong to the authenticated service artifact")
        require(hashlib.sha256(archive.read("output/realized-Cargo.lock")).hexdigest()
                == REALIZED_LOCK, "authenticated realized lock differs")
        for name in ("build.log", "resources.json", "admission.json"):
            require(archive.read("output/" + name) == (output / name).read_bytes(),
                    "hosted build log or resource evidence changed")
    resources = load(output / "resources.json")
    require(resources.get("exitCode") == 0 and resources.get("abortReason") is None
            and load(output / "admission.json").get("admitted") is True,
            "hosted build did not finish within its admitted resource envelope")
    payload = output / receipt["archive"]
    require(payload.stat().st_size == receipt["archiveBytes"]
            and digest(payload) == receipt["archiveSha256"], "retained unsigned archive changed")
    unsigned = root / "unsigned"
    with tarfile.open(payload, "r:gz") as package:
        for entry in package.getmembers():
            if entry.isfile():
                require(stat.S_IMODE((unsigned / entry.name).stat().st_mode) == entry.mode & 0o777,
                        "unsigned payload file mode changed")
    actual = {p.relative_to(unsigned).as_posix() for p in unsigned.rglob("*") if p.is_file()}
    require(actual == {item["path"] for item in receipt["files"]},
            "unsigned inputs contain missing or additional files")
    require(not any(p.is_symlink() for p in unsigned.rglob("*")), "unsigned input symlink")
    for item in receipt["files"]:
        path = unsigned / item["path"]
        require(path.stat().st_size == item["bytes"] and digest(path) == item["sha256"],
                "retained unsigned input changed")
    return proof


def local_build_contract(source, fips, receipt):
    """Bind exact recipe/target/features/patches/locks, not just FIPS's version."""
    require(digest(source / "Cargo.lock") == receipt["committedLockSha256"],
            "hosted and local committed locks differ")
    verifier = source / "scripts/verify-cargo-path-patch-lock.py"
    specs = subprocess.check_output(["python3", str(verifier), "--manifest-specs", str(fips)],
                                    text=True).splitlines()
    with tempfile.TemporaryDirectory(prefix="nvpn-hosted-lock-") as temporary:
        realized = pathlib.Path(temporary) / "Cargo.lock"
        subprocess.run(["python3", str(verifier), "--materialize", str(source / "Cargo.lock"),
                        str(realized), *specs], check=True, stdout=subprocess.PIPE)
        require(digest(realized) == REALIZED_LOCK, "local path patch realization differs")
    return {"application": APP, "fips": FIPS,
            "committedLockSha256": receipt["committedLockSha256"],
            "realizedLockSha256": REALIZED_LOCK, "pathPatchPackages": specs,
            "rustTarget": "aarch64-apple-ios", "rustProfile": "release",
            "rustPackage": "nostr-vpn-app-core", "defaultFeatures": False,
            "additionalFeatures": [], "producerCommit": receipt["producerCommit"],
            "canonicalRecipeSha256": digest(source / "tools/run-ios"),
            "localFipsWorkspaceRecipeSha256": digest(source / "scripts/local-fips-workspace.sh"),
            "pathPatchVerifierSha256": digest(verifier),
            "xcodeRecipes": receipt["recipes"], "toolchain": receipt["rustc"],
            "xcode": receipt["xcode"], "sdks": receipt["sdks"]}


def ios_executable_identity(path):
    segment, signature = macho_linkedit(path)
    if signature is None:
        require(segment["allocation"] == (segment["fileSize"] + 16383) // 16384 * 16384,
                "unsigned iOS LINKEDIT allocation differs from its content")
        return digest(path)
    with tempfile.TemporaryDirectory(prefix="nvpn-ios-hosted-signature-") as temporary:
        stripped = pathlib.Path(temporary) / "executable"
        shutil.copy2(path, stripped)
        subprocess.run(["codesign", "--remove-signature", str(stripped)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        canonicalize_stripped_linkedit(path, stripped)
        return digest(stripped)


def verify_ios_lineage(unsigned_app, signed_app):
    from ios_frozen_archive import bundle_identity, unsigned_content_manifest
    unsigned_identity = bundle_identity(unsigned_app, require_profiles=False)
    signed_identity = bundle_identity(signed_app)
    # Only plist serialization, code signatures, and their proven LINKEDIT
    # allocation may differ. Legacy frozen-archive identities stay unchanged.
    for app, identity in ((unsigned_app, unsigned_identity), (signed_app, signed_identity)):
        for key, relative in IOS_EXECUTABLES.items():
            identity[key] = ios_executable_identity(app / relative)
        sha, count = unsigned_content_manifest(app, canonicalize_plists=True)
        identity["unsignedContentManifestSha256"] = sha
        identity["unsignedContentFileCount"] = count
    require(unsigned_identity == signed_identity,
            "signed archive differs from hosted executable or non-signature content")
    return unsigned_identity


def ios_executable_audit(signed_app):
    audit_script = pathlib.Path(__file__).with_name("lib-mobile-ios-release-artifact.sh")
    app_executable = signed_app / "Nostr VPN"
    tunnel_executable = signed_app / "PlugIns/Nostr VPN Tunnel.appex/Nostr VPN Tunnel"
    subprocess.run(["bash", "-euo", "pipefail", "-c", '''
source "$1"
ios_release_network_audit_forbidden_runtime "$2" "hosted iOS Release app"
ios_release_network_audit_forbidden_runtime "$3" "hosted iOS Release Packet Tunnel"
ios_release_network_audit_packet_flow_binary "$3"
''', "hosted-final-executable-audit", str(audit_script),
        str(app_executable), str(tunnel_executable)], check=True)
    return {"auditorSha256": digest(audit_script),
            "appExecutableSha256": digest(app_executable),
            "packetTunnelExecutableSha256": digest(tunnel_executable),
            "forbiddenRuntimeAbsentFromAppAndTunnel": True,
            "privateUtunAbsentFromAppAndTunnel": True,
            "packetTunnelSupportedPacketFlowAbiPresent": True,
            "staticArchiveAuditExecutedLocally": False}


def prepare_ios_join_admission(root, signed_app):
    inputs = verified_inputs(root, "ios-join")
    unsigned_app = root / "unsigned/ios/.build/JoinReleaseDerivedData/Build/Products/Release-iphoneos/Nostr VPN.app"
    metadata = root / "unsigned/artifacts/mobile-ios/fips-linkage.json"
    return {"receiptSchema": 1, "artifactType": "hosted iOS join variant admission",
            "normalization": IOS_SIGNING_NORMALIZATION,
            "inputs": inputs, "unsignedIdentity": verify_ios_lineage(unsigned_app, signed_app),
            "finalExecutableAudit": ios_executable_audit(signed_app),
            "historicalFipsMetadata": load(metadata), "historicalFipsMetadataSha256": digest(metadata)}


def validate_ios_join_admission(receipt_path, receipt, signed_app):
    root = receipt_path.parent / "hosted-join"
    proof = receipt.get("hostedJoinBuild", {})
    require(proof.get("receiptSchema") == 1
            and proof.get("artifactType") == "hosted iOS join variant admission"
            and proof.get("normalization") == IOS_SIGNING_NORMALIZATION,
            "join variant has no independent hosted admission")
    require(proof.get("inputs") == verified_inputs(root, "ios-join"),
            "hosted join input binding changed")
    unsigned_app = root / "unsigned/ios/.build/JoinReleaseDerivedData/Build/Products/Release-iphoneos/Nostr VPN.app"
    require(proof.get("unsignedIdentity") == verify_ios_lineage(unsigned_app, signed_app),
            "signed join variant differs from its independently compiled hosted bytes")
    audit = proof.get("finalExecutableAudit", {})
    require(audit.get("auditorSha256") == digest(pathlib.Path(__file__).with_name(
                "lib-mobile-ios-release-artifact.sh"))
            and audit.get("appExecutableSha256") == digest(signed_app / "Nostr VPN")
            and audit.get("packetTunnelExecutableSha256") == digest(signed_app /
                "PlugIns/Nostr VPN Tunnel.appex/Nostr VPN Tunnel")
            and audit.get("forbiddenRuntimeAbsentFromAppAndTunnel") is True
            and audit.get("privateUtunAbsentFromAppAndTunnel") is True
            and audit.get("packetTunnelSupportedPacketFlowAbiPresent") is True
            and audit.get("staticArchiveAuditExecutedLocally") is False,
            "join variant lacks its final executable feature audit")
    metadata = root / "unsigned/artifacts/mobile-ios/fips-linkage.json"
    require(proof.get("historicalFipsMetadata") == load(metadata)
            and proof.get("historicalFipsMetadataSha256") == digest(metadata)
            and receipt.get("fipsCargoMetadataReceiptSha256") == digest(metadata)
            and receipt.get("fipsCheckoutPathSha256") == load(metadata)["checkoutPathSha256"],
            "join variant no longer binds its original hosted metadata")


def prepare_ios_admission(input_path, receipt_path, args, signed_app):
    root = receipt_path.parent / "hosted"
    require(pathlib.Path(input_path).resolve() == (root / "hosted-inputs.json").resolve(),
            "hosted inputs must be retained beside the frozen receipt")
    inputs = verified_inputs(root, "ios")
    metadata = root / "unsigned/artifacts/mobile-ios/fips-linkage.json"
    require(digest(metadata) == digest(pathlib.Path(args.fips_metadata)),
            "FIPS metadata is not the original hosted build proof")
    unsigned_app = root / "unsigned/dist/ios/NostrVpnIos.xcarchive/Products/Applications/Nostr VPN.app"
    require(pathlib.Path(args.archive).resolve() ==
            (receipt_path.parent.parent / "NostrVpnIos.xcarchive").resolve(),
            "hosted archive must use the canonical retained archive location")
    unsigned_identity = verify_ios_lineage(unsigned_app, signed_app)
    audit = ios_executable_audit(signed_app)
    return {"receiptSchema": 1, "artifactType": "hosted iOS archive admission",
            "normalization": IOS_SIGNING_NORMALIZATION,
            "inputs": inputs, "unsignedIdentity": unsigned_identity,
            "historicalFipsMetadata": load(metadata),
            "historicalFipsMetadataSha256": digest(metadata),
            "hostedBuildLogSha256": digest(root / "artifact/output/build.log"),
            "hostedResourcesReceiptSha256": digest(root / "artifact/output/resources.json"),
            "finalExecutableAudit": audit,
            "fipsDependencyRebuild": {"location": "hosted",
                "evidence": "authenticated canonical Release recipe cleans the three FIPS crates before the locked device build",
                "localRebuildMarkerCreated": False},
            "buildContract": local_build_contract(pathlib.Path(args.source_root),
                                                  pathlib.Path(args.fips_root),
                                                  inputs["producerReceipt"]),
            "validationSource": {"app": APP, "fips": FIPS,
                "fipsCheckoutPathSha256": hashlib.sha256(
                    str(pathlib.Path(args.fips_root).resolve()).encode()).hexdigest()}}


def validate_ios_admission(receipt_path, archive):
    """Every hosted frozen-archive consumer must call this mandatory check."""
    companion = receipt_path.parent / "hosted-admission.json"
    if archive.get("receiptSchema") == 1:
        require("hostedBuildSha256" not in archive and not companion.exists(),
                "hosted archive cannot be downgraded to local schema 1")
        return None
    require(archive.get("receiptSchema") == 2, "unsupported frozen archive schema")
    admission = load(companion)
    proof = admission["hostedBuild"]
    require(admission.get("receiptSchema") == 1
            and admission.get("artifactType") == "signed hosted iOS archive admission"
            and admission.get("archiveReceiptSha256") == digest(receipt_path)
            and canonical_digest(proof) == archive.get("hostedBuildSha256"),
            "hosted admission is absent, changed or bound to another frozen archive")
    require(proof.get("receiptSchema") == 1
            and proof.get("artifactType") == "hosted iOS archive admission"
            and proof.get("normalization") == IOS_SIGNING_NORMALIZATION,
            "wrong hosted admission proof")
    inputs = verified_inputs(receipt_path.parent / "hosted", "ios")
    require(proof["inputs"] == inputs, "hosted input binding changed")
    unsigned_app = receipt_path.parent / "hosted/unsigned/dist/ios/NostrVpnIos.xcarchive/Products/Applications/Nostr VPN.app"
    signed_app = receipt_path.parent.parent / "NostrVpnIos.xcarchive/Products/Applications/Nostr VPN.app"
    require(verify_ios_lineage(unsigned_app, signed_app) == proof.get("unsignedIdentity"),
            "current hosted bytes differ from the frozen admission identity")
    audit = proof.get("finalExecutableAudit", {})
    require(audit.get("forbiddenRuntimeAbsentFromAppAndTunnel") is True
            and audit.get("privateUtunAbsentFromAppAndTunnel") is True
            and audit.get("packetTunnelSupportedPacketFlowAbiPresent") is True
            and audit.get("staticArchiveAuditExecutedLocally") is False
            and audit.get("auditorSha256") == digest(
                pathlib.Path(__file__).with_name("lib-mobile-ios-release-artifact.sh")),
            "hosted archive lacks the qualified final-executable feature audit")
    require(audit.get("appExecutableSha256") == digest(signed_app / "Nostr VPN")
            and audit.get("packetTunnelExecutableSha256") == digest(
                signed_app / "PlugIns/Nostr VPN Tunnel.appex/Nostr VPN Tunnel"),
            "current frozen executables differ from the admitted feature audit")
    rebuild = proof.get("fipsDependencyRebuild", {})
    require(rebuild.get("location") == "hosted" and rebuild.get("localRebuildMarkerCreated") is False,
            "hosted FIPS rebuild was misrepresented as a local rebuild")
    from ios_frozen_archive import bundle_identity
    signed_identity = bundle_identity(signed_app)
    for key, value in proof["unsignedIdentity"].items():
        if key not in {"unsignedContentManifestSha256", "unsignedContentFileCount"}:
            # The frozen receipt keeps its original signing-dependent hashes;
            # bind them to the current signed bytes as well as proving lineage.
            expected = signed_identity[key] if key in IOS_EXECUTABLES else value
            require(archive.get("identity", {}).get(key) == expected,
                    "frozen archive identity differs from hosted input at " + key)
    evidence_root = receipt_path.parent / "hosted/artifact/output"
    require(proof.get("hostedBuildLogSha256") == digest(evidence_root / "build.log")
            and proof.get("hostedResourcesReceiptSha256") == digest(evidence_root / "resources.json"),
            "hosted build log/resource binding changed")
    metadata = proof["historicalFipsMetadata"]
    metadata_path = receipt_path.parent / "hosted/unsigned/artifacts/mobile-ios/fips-linkage.json"
    require(metadata == load(metadata_path)
            and proof["historicalFipsMetadataSha256"] == digest(metadata_path),
            "hosted build metadata was replaced by validation metadata")
    require(archive.get("appGitSha") == APP["commit"]
            and archive.get("appGitTree") == APP["tree"]
            and archive.get("fipsGitSha") == FIPS["commit"]
            and archive.get("fipsGitTree") == FIPS["tree"]
            and archive.get("fipsCheckoutPathSha256") == metadata["checkoutPathSha256"]
            and archive.get("fipsCargoMetadataReceiptSha256") == proof["historicalFipsMetadataSha256"],
            "frozen archive no longer binds original hosted source/build provenance")
    return admission


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--platform", choices=tuple(PRODUCERS), required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--max-bytes", type=int, required=True)
    parser.add_argument("--reserve-bytes", type=int, required=True)
    fetch(parser.parse_args())


if __name__ == "__main__":
    main()
