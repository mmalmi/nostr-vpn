#!/usr/bin/env python3
"""Hosted-only, nonpublishing OCI producer for one frozen seed candidate."""
import argparse
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from seed_hosted_proof import CachedRunGuard, canonical, require, sha256, verify_source, verify_toolchain
from seed_hosted_runtime import Runner, capture
from seed_oci_proof import verify_oci

FILES = (
    ".github/workflows/seed-oci-candidate.yml", "scripts/seed-hosted-inputs.json",
    "scripts/seed_hosted_candidate.py", "scripts/seed_hosted_proof.py",
    "scripts/seed_hosted_runtime.py", "scripts/seed_oci_proof.py",
    "scripts/test_seed_hosted_candidate.py",
)


def identity():
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("GITHUB_REPOSITORY") == "mmalmi/nostr-vpn" and
            platform.system() == "Linux" and platform.machine() == "x86_64",
            "This producer requires its dedicated hosted Linux runner")
    require(sys.version_info[:2] == (3, 12), "Python 3.12 producer runtime required")
    for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA"):
        require(re.fullmatch(r"[0-9a-f]{40}", os.environ.get(key, "")),
                "Missing immutable workflow identity")
    require(os.environ["GITHUB_SHA"] == os.environ["GITHUB_WORKFLOW_SHA"],
            "Workflow and producer identities differ")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]*", os.environ.get(key, "")), "Invalid run identity")
    return {"commit": os.environ["GITHUB_SHA"], "workflowCommit": os.environ["GITHUB_WORKFLOW_SHA"],
            "repository": os.environ["GITHUB_REPOSITORY"], "runId": os.environ["GITHUB_RUN_ID"],
            "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "workflowRef": os.environ.get("GITHUB_WORKFLOW_REF", ""),
            "runnerImage": os.environ.get("ImageOS", ""),
            "runnerImageVersion": os.environ.get("ImageVersion", "")}


def download_buildx(runner):
    pin = runner.pins["buildx"]
    path = runner.buildx
    digest = hashlib.sha256()
    count = 0
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(pin["url"], headers={"User-Agent": "nvpn-seed-producer"})
    with opener.open(request, timeout=15) as source, path.open("xb") as output:
        require(source.geturl().startswith("https://"), "Insecure Buildx redirect")
        while block := source.read(65536):
            count += len(block)
            require(count <= pin["bytes"], "Buildx download exceeds pinned size")
            output.write(block)
            digest.update(block)
            runner.check()
    require(count == pin["bytes"] and digest.hexdigest() == pin["sha256"],
            "Buildx download does not match the reviewed immutable pin")
    path.chmod(0o755)
    version = runner.run([str(path), "version"]).strip()
    require(pin["version"] in version and pin["commit"] in version,
            "Buildx executable identity mismatch")
    return version


def source_and_producer(runner, producer, source):
    def git(root, *args):
        return runner.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                           "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
                           *args], cwd=root)
    require(git(producer, "rev-parse", "HEAD").strip() == runner.identity["commit"],
            "Producer checkout identity mismatch")
    require(not git(producer, "status", "--porcelain", "--untracked-files=all").strip(),
            "Producer checkout is not clean")
    parent = "a99bfd9b9dcb5ebf2857d77bfab8bf7c3f26d2b8"
    support_parent = "6431b80c17185cf1981be97d9ee358d8faec1f4f"
    require(git(producer, "show", "-s", "--format=%P", "HEAD").strip() == parent and
            git(producer, "show", "-s", "--format=%P", parent).strip() == support_parent and
            git(producer, "show", "-s", "--format=%P", support_parent).strip() ==
            runner.pins["product"]["commit"], "Producer lineage differs from the reviewed support parent")
    changes = set(git(producer, "diff", "--name-only", "--no-renames",
                      runner.pins["product"]["commit"], "HEAD").splitlines())
    require(changes == set(FILES), "Producer changes extend beyond support-only scope")
    rows = verify_source(source, runner.pins["product"], git)
    return git, rows, {name: sha256((producer / name).read_bytes()) for name in FILES}


def build_arguments(runner, source, output, metadata, target=None, load=False,
                    progress="plain"):
    args = [str(runner.buildx), "build", "--builder", runner.name, "--platform", "linux/amd64",
            "--file", str(source / "umbrel/Dockerfile"), "--provenance=false",
            "--build-arg", "SOURCE_DATE_EPOCH=" + str(runner.pins["product"]["sourceDateEpoch"]),
            "--metadata-file", str(metadata), "--progress", progress]
    if target:
        args += ["--target", target, "--tag", runner.name + "-toolchain"]
    exporter = "docker" if load else "oci"
    args += ["--output", "type=" + exporter + ",dest=" + str(output) + ",rewrite-timestamp=true",
             str(source)]
    return args


def inspect_realized_builder(runner, source):
    stage = runner.work / "toolchain-stage.tar"
    metadata = runner.output / "toolchain-stage-metadata.json"
    guard = CachedRunGuard()
    runner.run(build_arguments(runner, source, stage, metadata,
                               target="rust-builder", load=True, progress="rawjson"),
               timeout=300, capture_output=False, progress_guard=guard)
    cached_steps = guard.finish()
    # Free and verify the 6 GiB builder scope before the 256 MiB inspection scope.
    builder_closure = runner.stop_builder()
    require(builder_closure["closed"] and runner.container is None and runner.group is None,
            "BuildKit must be closed before toolchain inspection")
    runner.check()
    tag = runner.name + "-toolchain"
    require(not runner.run(["docker", "image", "ls", "-q", "--no-trunc", tag]).strip(),
            "Inspection image tag already exists")
    expected_id = json.loads(metadata.read_text())["containerimage.config.digest"]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", expected_id), "Invalid stage config identity")
    runner.inspection_image, runner.inspection_image_id = tag, expected_id
    runner.save_state()
    runner.run(["docker", "load", "--input", str(stage)], timeout=120)
    image = runner.inspect("image", runner.inspection_image)
    require(image["Id"] == expected_id, "Loaded toolchain image identity mismatch")
    runner.inspection_container = runner.name + "-inspect"
    runner.save_state()
    command = ("printf '==rustc==\\n'; rustc -Vv; printf '==cargo==\\n'; cargo -V; "
               "printf '==gcc==\\n'; gcc -dumpfullversion -dumpversion; "
               "printf '==os==\\n'; cat /etc/os-release; printf '==packages==\\n'; "
               "dpkg-query -W clang libclang-dev libdbus-1-dev pkg-config gcc libc6 binutils")
    result = runner.run([
        "docker", "run", "--name", runner.inspection_container,
        "--label", "io.nostr-vpn.seed-job=" + runner.owner,
        "--label", "io.nostr-vpn.seed-source=" + runner.pins["product"]["commit"],
        "--network=none", "--read-only", "--cpus=1", "--memory=256m", "--memory-swap=256m",
        "--pids-limit=32", "--entrypoint", "sh", runner.inspection_image, "-ec", command],
        timeout=30)
    verified = verify_toolchain(result, runner.pins["toolchain"])
    return {"stageImageId": image["Id"], "observations": verified, "cachedRunSteps": cached_steps,
            "builderClosureBeforeInspection": builder_closure,
            "method": "cached export of the exact completed rust-builder target; no source changes"}


def recover(work, pins, ident):
    state_path = work / "owned-resources.json"
    if not state_path.exists():
        return
    require(state_path.is_file() and not state_path.is_symlink(), "Invalid ownership ledger")
    state = json.loads(state_path.read_text())
    require(state["identity"] == ident and state["product"] == pins["product"]["commit"] and
            state["owner"] == ident["runId"] + "-" + ident["runAttempt"] and
            state["name"] == "nvpn-seed-" + state["owner"], "Recovery ownership mismatch")
    if state["closed"]:
        return
    # Reconstruct only cleanup fields; never initialize a second builder or start a build.
    runner = Runner.__new__(Runner)
    runner.work, runner.output, runner.pins = work, work / "output", pins
    runner.identity, runner.owner, runner.name = ident, state["owner"], state["name"]
    runner.limits, runner.buildx = pins["limits"], work / "tools/buildx"
    runner.container = state["container"]
    runner.inspection_container, runner.inspection_image = state["inspectionContainer"], state["inspectionImage"]
    runner.inspection_image_id = state["inspectionImageId"]
    runner.volume_created, runner.builder_created = state["volumeCreated"], state["builderCreated"]
    runner.group = None
    runner.environment = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                          "HOME": str(work / "home"), "DOCKER_CONFIG": str(work / "docker"),
                          "DOCKER_HOST": "unix:///var/run/docker.sock",
                          "BUILDX_CONFIG": str(work / "buildx"), "LANG": "C.UTF-8", "TZ": "UTC"}
    closure = runner.cleanup(runner.buildx)
    (runner.output / "recovery-closure.json").write_bytes(canonical(closure) + b"\n")
    require(closure["closed"], "Recovery cleanup is incomplete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    ident = identity()
    producer = Path(__file__).resolve().parent.parent
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    require(producer == workspace / "producer", "Unexpected producer checkout")
    source = workspace / "product"
    require(source.resolve() == source, "Product checkout must not be a symlink")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    work = temp / ("nvpn-seed-" + ident["runId"] + "-" + ident["runAttempt"])
    pins = json.loads((producer / "scripts/seed-hosted-inputs.json").read_text())
    require(pins["schema"] == 1, "Unsupported producer input schema")
    if args.cleanup:
        recover(work, pins, ident)
        return
    require(not work.exists(), "Producer work directory already exists")
    work.mkdir(mode=0o700)
    cpus = sorted(os.sched_getaffinity(0))[:pins["limits"]["cpu"]]
    require(len(cpus) == pins["limits"]["cpu"], "Not enough CPUs")
    os.sched_setaffinity(0, cpus)
    require(capture(["docker", "context", "show"]).strip() == "default" and
            json.loads(capture(["docker", "context", "inspect", "default",
                                "--format", "{{json .Endpoints.docker.Host}}"])) ==
            "unix:///var/run/docker.sock", "Only the dedicated local Docker engine is allowed")
    runner = Runner(work, pins, ident)
    receipt = {"schema": 1, "accepted": False, "candidateBuildOnly": True,
               "releaseAccepted": False, "product": pins["product"], "producer": ident,
               "limits": pins["limits"], "resourceBudgetIsMeasuredColdPeak": False}
    failure = None
    try:
        git, rows, producer_files = source_and_producer(runner, producer, source)
        receipt["producerFiles"] = producer_files
        (runner.output / "source-context.json").write_bytes(canonical(rows) + b"\n")
        receipt["buildxVersion"] = download_buildx(runner)
        receipt["buildkit"] = runner.create_builder(runner.buildx)
        candidate = runner.output / "candidate.oci.tar"
        metadata_path = runner.output / "build-metadata.json"
        runner.run(build_arguments(runner, source, candidate, metadata_path),
                   timeout=pins["limits"]["timeoutSeconds"], capture_output=False)
        receipt["toolchain"] = inspect_realized_builder(runner, source)
        verify_source(source, pins["product"], git)
        metadata = json.loads(metadata_path.read_text())
        with candidate.open("rb") as stream:
            receipt["image"] = verify_oci(stream, pins["limits"]["ociBytes"],
                                         metadata["containerimage.digest"])
        require(receipt["image"]["configDigest"] == metadata["containerimage.config.digest"],
                "Buildx config differs from exported image")
        digest = hashlib.sha256()
        with candidate.open("rb") as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
        receipt["archive"] = {"sha256": digest.hexdigest(), "bytes": candidate.stat().st_size}
        receipt["producer"]["python"] = sys.version
        receipt["docker"] = json.loads(runner.run(["docker", "version", "--format", "{{json .}}"]))
        runner.check()
        receipt["accepted"] = True
    except Exception as error:
        failure = type(error).__name__ + ": " + str(error)
        receipt["failure"] = failure
    finally:
        receipt["closure"] = runner.cleanup(runner.buildx)
        receipt["accepted"] = receipt["accepted"] and receipt["closure"]["closed"]
        receipt["resourceSamples"] = runner.samples
        receipt["elapsedSeconds"] = time.monotonic() - runner.started
        (runner.output / "producer-receipt.json").write_bytes(canonical(receipt) + b"\n")
    require(receipt["accepted"], failure or "Producer cleanup was incomplete")


if __name__ == "__main__":
    main()
