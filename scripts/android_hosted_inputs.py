#!/usr/bin/env python3
"""Authenticate retained Android producer output without building or downloading."""

import hashlib
import json
import pathlib
import re
import subprocess

from android_hosted_content import canonical_digest, digest, require, safe_name, zip_identity

APP = {"commit": "52a1f8eee3cf19c5bc467a3ccf39d3d6d74437f4", "tree": "2f722bd2e0f34e7b71cae665cce74c3080c99661"}
FIPS = {"commit": "d0b18f2d1b2e97d42fa8460a0c70a8dffeaa2552", "tree": "08ceced056b8592a2b2c840c4c276bf01cf28c85"}
FIPS_VERSION = "0.4.117"
COMMITTED_LOCK = "1d72aac7e6e5355dc5c903a7f39ae376172739e1c6cd954cadcc88bec33bfb79"
REALIZED_LOCK = "41067773c75d291993622ac7d0a66ac77e3ce050ff6b9a646466a413f5cb065a"
SCRIPTS = {
    "tools/run-android": "bcf80370bb56d312769ec79a548359b4db6ae67f327b0f6974ed5aea205c7bc9",
    "scripts/release_common.sh": "25445a5829bef66b3fa25d934498964e54cc3762cf5ef74026dd07c29e1fffe7",
    "scripts/local-fips-workspace.sh": "05019222d5f64e54ad0637df8c88f15bd9bffba1775aebd70aba1aa335c9bf18",
    "scripts/prepare-android-release-from-bundle.sh": "9793ffef71e61984c7b065330e319e275792e6bdd94cfadbebc95644ca4989cf",
    "scripts/verify-cargo-path-patch-lock.py": "46debe878143664e33288494535aa95c9ebb9bbb68ad40405a4535befe64f653",
}
BUNDLETOOL_SHA = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
# Admission stays closed until the successful platform job and service artifact
# are reviewed. A producer receipt cannot supply or override these pins.
SERVICE = {
    "repository": "mmalmi/nostr-vpn", "workflow": ".github/workflows/android-release-inputs.yml",
    "producerCommit": "c172eb1f04d88d57e2e2c610456c42a2c63167c7", "runId": "41925607166",
    "runAttempt": None, "jobId": None, "jobName": "inputs", "jobConclusion": "success",
    "artifactId": None, "artifactName": "android-release-inputs-52a1f8ee",
    "artifactBytes": None, "artifactSha256": None,
}


def load(path):
    require(path.is_file() and not path.is_symlink(), "required Android proof is absent or linked")
    require(path.stat().st_size <= 16 * 1024**2, "Android JSON proof exceeds its bound")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON proof key")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def write(path, value):
    require(not path.exists() and not path.is_symlink(), "Android proof output must be fresh")
    with path.open("x") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")


def require_service(authentication):
    require(all(value is not None for value in SERVICE.values()),
            "successful Android hosted artifact has not been pinned")
    require(authentication == SERVICE, "Android hosted job/artifact differs from admitted producer")


def authenticate_service(run, job, artifact):
    require_service(SERVICE)
    require(run.get("id") == int(SERVICE["runId"]) and run.get("head_sha") == SERVICE["producerCommit"]
            and run.get("path") == SERVICE["workflow"]
            and run.get("repository", {}).get("full_name") == SERVICE["repository"]
            and str(run.get("run_attempt")) == SERVICE["runAttempt"], "Android workflow identity differs")
    require(job.get("id") == SERVICE["jobId"] and job.get("run_id") == run["id"]
            and str(job.get("run_attempt")) == SERVICE["runAttempt"]
            and job.get("head_sha") == SERVICE["producerCommit"]
            and job.get("name") == SERVICE["jobName"] and job.get("status") == "completed"
            and job.get("conclusion") == "success", "Android platform job did not succeed on the admitted attempt")
    require(artifact.get("id") == SERVICE["artifactId"] and artifact.get("name") == SERVICE["artifactName"]
            and artifact.get("size_in_bytes") == SERVICE["artifactBytes"] and artifact.get("expired") is False
            and artifact.get("digest") == "sha256:" + SERVICE["artifactSha256"]
            and artifact.get("workflow_run", {}).get("id") == run["id"]
            and artifact.get("workflow_run", {}).get("head_sha") == SERVICE["producerCommit"],
            "Android service artifact differs")
    return dict(SERVICE)


def validate_producer(receipt, payload):
    expected = {"schema": 1, "platform": "android", "configuration": "Release",
        "source": {"app": APP, "fips": FIPS}, "canonicalScripts": SCRIPTS,
        "distributionSigned": False, "runtimeTestsExecuted": False, "releaseAccepted": False,
        "signingInputsAbsent": True, "signed": False, "buildExitCode": 0,
        "rust": {"target": "aarch64-linux-android", "package": "nostr-vpn-app-core",
                 "profile": "release", "defaultFeatures": True, "additionalFeatures": []},
        "producer": {"commit": SERVICE["producerCommit"], "runId": SERVICE["runId"],
                     "attempt": SERVICE["runAttempt"], "job": "inputs", "repository": SERVICE["repository"]}}
    require(all(receipt.get(key) == value for key, value in expected.items()), "Android source/recipe/target contract differs")
    require(receipt.get("imageVersion") and receipt.get("toolVersions", {}).get("rustc")
            == "rustc 1.95.0 (59807616e 2026-04-14)", "Android producer toolchain identity is missing")
    for name, expected_sha in (("committed-Cargo.lock", COMMITTED_LOCK), ("realized-Cargo.lock", REALIZED_LOCK)):
        require(digest(payload / "provenance" / name) == expected_sha, "Android locked dependency graph differs")
    pins = load(payload / "provenance/inputs.json")
    require(pins.get("app") == APP and pins.get("fips") == {**FIPS, "version": FIPS_VERSION}
            and pins.get("target") == "aarch64-linux-android" and pins.get("abi") == "arm64-v8a"
            and pins.get("realizedCargoLockSha256") == REALIZED_LOCK
            and pins.get("hostedNativeComponentsQualified") is True,
            "Android producer input pins differ")
    metadata = load(payload / "provenance/fips-linkage.json")
    require(metadata.get("checkoutHead") == FIPS["commit"] and metadata.get("checkoutTree") == FIPS["tree"]
            and metadata.get("fipsCoreVersion") == FIPS_VERSION
            and metadata.get("checkoutPathSha256") == receipt.get("fipsCheckoutPathSha256")
            and metadata.get("source") == "exact clean local Cargo path dependency",
            "original hosted Android FIPS metadata differs")
    files = receipt["files"]
    marker = files["provenance/forced-rebuild.marker"]
    require(receipt.get("forcedRebuild") == marker, "Android forced-rebuild marker differs")
    marker_ns = marker["originalMtimeNs"]
    require(type(marker_ns) is int and marker_ns > 0, "Android original rebuild time is absent")
    deps = [name for name in files if name.startswith("provenance/dep-info/") and name.endswith(".d")]
    require(deps, "Android original dependency evidence is absent")
    for name in deps:
        require(files[name]["originalMtimeNs"] >= marker_ns, "Android original dep-info predates rebuild")
        text = (payload / name).read_text()
        prefixes = re.findall(r"(/[^\s:]+?)/crates/fips-core(?:/|\s)", text)
        require(any(hashlib.sha256(prefix.encode()).hexdigest() == metadata["checkoutPathSha256"]
                    for prefix in prefixes), "Android dep-info does not bind the hosted FIPS path")
    require(files["unsigned/app-release.aab"]["originalMtimeNs"] >= marker_ns
            and receipt["compiledJni"]["originalMtimeNs"] >= marker_ns,
            "Android AAB or compiled JNI predates forced rebuild")
    bundle = zip_identity(payload / "unsigned/app-release.aab")
    native = {name: value for name, value in bundle.items() if name.startswith("base/lib/") and name.endswith(".so")}
    require(set(native) == set(receipt["jniPayloads"]), "Android JNI payload set differs")
    for name, identity in native.items():
        require(re.fullmatch(r"base/lib/arm64-v8a/[^/]+\.so", name), "Android JNI ABI differs")
        exported = files["unsigned/jni/" + name.removeprefix("base/lib/")]
        recorded = receipt["jniPayloads"][name]
        require(recorded["origin"] == "unsigned AAB entry"
                and recorded["sha256"] == exported["sha256"] == identity["sha256"]
                and recorded["size"] == exported["size"] == identity["bytes"], "Android JNI bytes differ")
    compiled = receipt["compiledJni"]
    require(all(compiled[key] == receipt["jniPayloads"]["base/lib/arm64-v8a/libnostr_vpn_app_core.so"][key]
                for key in ("sha256", "size")), "Android compiled JNI differs from the AAB")
    resources = load(payload / "provenance/resources.json")
    require(resources.get("abortReason") is None and resources.get("commands")
            and all(command.get("exitCode") == 0 for command in resources["commands"]),
            "Android hosted build did not complete inside its admitted envelope")
    return metadata


def verified_inputs(root, authentication=None):
    require(root.is_dir() and not root.is_symlink(), "Android hosted input root must be real")
    root = root.resolve()
    retained_proof = None
    if authentication is None:
        retained_proof = load(root / "hosted-inputs.json")
        require(retained_proof.get("receiptSchema") == 1 and retained_proof.get("platform") == "android",
                "wrong Android input proof schema")
        authentication = retained_proof.get("authentication")
    require_service(authentication)
    package, payload = root / "github-artifact.zip", root / "payload"
    require(payload.is_dir() and not payload.is_symlink() and payload.resolve().parent == root,
            "Android payload must be a real contained directory")
    require(package.is_file() and not package.is_symlink() and package.stat().st_size == SERVICE["artifactBytes"]
            and digest(package) == SERVICE["artifactSha256"], "retained Android service artifact changed")
    zipped = zip_identity(package)
    receipt_path = payload / "provenance/receipt.json"
    receipt = load(receipt_path)
    files = receipt["files"]
    require(isinstance(files, dict) and len(files) > 0, "Android export manifest is absent")
    expected = set(files) | {"provenance/receipt.json"}
    require(set(zipped) == expected, "Android service ZIP and export manifest differ")
    actual = set()
    for path in payload.rglob("*"):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), "linked or special Android retained input")
        if path.is_file():
            actual.add(path.relative_to(payload).as_posix())
    require(actual == expected, "Android retained payload has missing or extra files")
    for name, identity in zipped.items():
        safe_name(name)
        path = payload / name
        require(path.stat().st_size == identity["bytes"] and digest(path) == identity["sha256"],
                "Android retained file differs from its service ZIP")
        if name in files:
            require(files[name]["size"] == identity["bytes"] and files[name]["sha256"] == identity["sha256"],
                    "Android producer manifest differs from its payload")
    metadata = validate_producer(receipt, payload)
    result = {"authentication": authentication, "producerReceiptSha256": digest(receipt_path),
              "producerReceipt": receipt, "historicalFipsMetadata": metadata}
    if retained_proof is not None:
        require(all(retained_proof.get(key) == value for key, value in result.items()),
                "Android retained authentication proof changed")
    return result


def authenticate_inputs(root):
    require_service(SERVICE)
    def api(path):
        return json.loads(subprocess.check_output(["gh", "api", "repos/" + SERVICE["repository"] + path]))
    authentication = authenticate_service(api("/actions/runs/" + SERVICE["runId"]),
        api("/actions/jobs/" + str(SERVICE["jobId"])), api("/actions/artifacts/" + str(SERVICE["artifactId"])))
    proof = verified_inputs(root, authentication)
    write(root / "hosted-inputs.json", {"receiptSchema": 1, "platform": "android", **proof})
