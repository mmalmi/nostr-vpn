"""Build one exact diagnostic daemon on a dedicated hosted Linux runner."""
import hashlib
import difflib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

APP_SHA = "5c1b2f0606f18387ace32f5712dde9b63a274620"
APP_TREE = "bc66adf87c8f0a8fe8cb1df4ccc3b4462e369335"
FIPS_SHA = "e8ffed70d96a29a6a0355d5979e7111987f8d3b2"
FIPS_TREE = "50681e1845a93130390eb3895d24c04332c45085"
BASE = "ubuntu@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc"
TARGET = "x86_64-unknown-linux-musl"

app, fips, output = (Path(arg).resolve() for arg in sys.argv[1:])
assert os.uname().sysname == "Linux" and os.uname().machine == "x86_64"
assert not output.exists()
evidence = output / "evidence"
evidence.mkdir(parents=True)
started = time.monotonic()
receipt = {"success": False, "diagnostic_build_only": True, "runtime_acceptance": False,
           "workflow_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
           "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "commands": [], "base_image": BASE}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture(command, cwd=None):
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def run(name, command, cwd=None, env=None):
    log = evidence / (name + ".log")
    start = time.monotonic()
    with log.open("w") as stream:
        done = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
    row = {"name": name, "exit_code": done.returncode, "seconds": time.monotonic() - start,
           "log": log.name, "log_bytes": log.stat().st_size, "log_sha256": sha(log)}
    receipt["commands"].append(row)
    print(json.dumps(row), flush=True)
    if done.returncode:
        print("\n".join(log.read_text(errors="replace").splitlines()[-40:]), flush=True)
    done.check_returncode()
    return log


def files(root):
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    result = {}
    for name in names:
        if not name:
            continue
        path = root / name
        result[name] = (hashlib.sha256(os.readlink(path).encode()).hexdigest()
                        if path.is_symlink() else sha(path))
    return result


def source(root, expected_sha, expected_tree):
    assert capture(["git", "rev-parse", "HEAD"], root) == expected_sha
    assert capture(["git", "rev-parse", "HEAD^{tree}"], root) == expected_tree
    assert not capture(["git", "status", "--porcelain"], root)
    return files(root)


def fingerprint(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def verify_archive(work, expected, exceptions):
    for name, expected_hash in expected.items():
        path = work / name
        actual = (hashlib.sha256(os.readlink(path).encode()).hexdigest()
                  if path.is_symlink() else sha(path))
        assert actual == exceptions.get(name, expected_hash), "archive source changed: " + name


def locked_driver(original):
    """Retain canonical build mechanics with the approved materialized lock."""
    adapted = original
    archive_line = 'git -C "$WORKSPACE" archive --format=tar HEAD | tar -x -C "$WORK_DIR"\n'
    assert adapted.count(archive_line) == 1
    adapted = adapted.replace(archive_line, archive_line +
        'cp -- "$NVPN_MARKED_EXPECTED_LOCK" "$WORK_DIR/Cargo.lock"\n')
    for suffix, package in (("ENDPOINT", "nvpn-fips-endpoint"),
                            ("CORE", "nvpn-fips-core"),
                            ("IDENTITY", "nvpn-fips-identity")):
        variable = "NVPN_FIPS_" + suffix + "_PATCH_PATH"
        block = ('if [[ -n ${' + variable + ':-} ]]; then\n'
                 '  cargo_config_args+=(--config "patch.crates-io.' + package +
                 '.path=\\"${' + variable + '}\\"")\n'
                 '  cargo_lock_args=()\nfi\n')
        assert adapted.count(block) == 1
        adapted = adapted.replace(block, block.replace('cargo_lock_args=()', 'cargo_lock_args=(--locked)'))
        update = ('if [[ -n ${' + variable + ':-} ]]; then\n'
                  '  cargo "${cargo_config_args[@]}" update -p ' + package + '\nfi\n')
        assert adapted.count(update) == 1
        adapted = adapted.replace(update, '')
    build = 'cargo "${cargo_config_args[@]}" build "${cargo_lock_args[@]}"'
    assert adapted.count(build) == 1
    adapted = adapted.replace(build, 'cargo "${cargo_config_args[@]}" build --frozen')
    fetch = 'cargo "${cargo_config_args[@]}" fetch "${cargo_lock_args[@]}" --target "$TARGET"'
    assert adapted.count(fetch) == 1
    return adapted.replace(fetch, fetch + ' --target x86_64-unknown-linux-gnu')


try:
    before_app = source(app, APP_SHA, APP_TREE)
    before_fips = source(fips, FIPS_SHA, FIPS_TREE)
    receipt["inputs"] = {
        "app_sha": APP_SHA, "app_tree": APP_TREE, "app_files_sha256": fingerprint(before_app),
        "fips_sha": FIPS_SHA, "fips_tree": FIPS_TREE, "fips_files_sha256": fingerprint(before_fips),
        "canonical_wrapper_sha256": sha(app / "scripts/build-nvpn-linux-musl"),
        "base_dockerfile_sha256": sha(app / "Dockerfile.linux-vm-gate"),
        "lock_verifier_sha256": sha(app / "scripts/verify-cargo-path-patch-lock.py"),
        "helper_sha256": sha(__file__),
        "workflow_sha256": sha(Path(__file__).resolve().parents[1] / ".github/workflows/marked-seed-daemon.yml"),
    }
    disk = os.statvfs(output)
    receipt["resources_before"] = {"disk_available_bytes": disk.f_bavail * disk.f_frsize,
                                   "meminfo": Path("/proc/meminfo").read_text()}
    verifier = app / "scripts/verify-cargo-path-patch-lock.py"
    packages = capture(["python3", str(verifier), "--manifest-specs", str(fips)]).splitlines()
    assert len(packages) == 8
    expected_lock = capture(["python3", str(verifier), "--expected-sha256", str(app / "Cargo.lock"), *packages])
    assert expected_lock == "cc7015e369b655778dd391541d296c20036bf2a8475cab1d2ea2d2aa8692d264"
    receipt["approved_path_packages"] = packages
    receipt["expected_realized_lock_sha256"] = expected_lock
    shutil.copyfile(app / "Cargo.lock", evidence / "Cargo.lock.committed")

    # Prove the approved lock resolves before building the image or daemon.
    run("resolver-toolchain", ["rustup", "toolchain", "install", "1.95.0", "--profile", "minimal"])
    run("resolver-version", ["cargo", "+1.95.0", "--version", "--verbose"])
    preflight = output / "lock-preflight"
    preflight.mkdir()
    archive = output / "app.tar"
    subprocess.run(["git", "archive", "--format=tar", "--output=" + str(archive), "HEAD"], cwd=app, check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(preflight)], check=True)
    (preflight / ".fips-patch").symlink_to(fips, target_is_directory=True)
    manifest = (app / "Cargo.toml").read_text().replace(
        'exclude = ["linux"]',
        'exclude = ["linux", ".fips-patch", ".nostr-pubsub-patch", ".cashu-service-patch", "cashu_spilman_channels"]')
    (preflight / "Cargo.toml").write_text(manifest)
    resolver = ["cargo", "+1.95.0"]
    for package, directory in (("nvpn-fips-endpoint", "fips-endpoint"),
                               ("nvpn-fips-core", "fips-core"),
                               ("nvpn-fips-identity", "fips-identity")):
        resolver += ["--config", 'patch.crates-io.' + package + '.path=' + json.dumps(str(fips / "crates" / directory))]
    run("expected-lock", ["python3", str(verifier), "--materialize", str(app / "Cargo.lock"), str(evidence / "Cargo.lock.expected"), *packages])
    shutil.copyfile(evidence / "Cargo.lock.expected", preflight / "Cargo.lock")
    try:
        run("resolve-locked", resolver + ["metadata", "--locked", "--format-version", "1",
                                          "--filter-platform", TARGET], cwd=preflight)
    finally:
        shutil.copyfile(preflight / "Cargo.lock", evidence / "Cargo.lock.preflight")
        delta = "".join(difflib.unified_diff(
            (evidence / "Cargo.lock.expected").read_text().splitlines(keepends=True),
            (preflight / "Cargo.lock").read_text().splitlines(keepends=True),
            fromfile="expected", tofile="resolved"))
        (evidence / "lock-preflight.diff").write_text(delta)
    receipt["preflight_lock_sha256"] = sha(preflight / "Cargo.lock")
    verify_archive(preflight, before_app, {"Cargo.toml": hashlib.sha256(manifest.encode()).hexdigest(),
                                          "Cargo.lock": receipt["preflight_lock_sha256"]})
    assert source(app, APP_SHA, APP_TREE) == before_app
    assert source(fips, FIPS_SHA, FIPS_TREE) == before_fips
    run("preflight-lock", ["python3", str(verifier), "--validate", str(app / "Cargo.lock"), str(preflight / "Cargo.lock"), *packages])

    image_context = output / "image"
    image_context.mkdir()
    original = (app / "Dockerfile.linux-vm-gate").read_text()
    assert original.startswith("FROM ubuntu:24.04\n")
    assert original.count("ARG RUST_TOOLCHAIN=1.95.0") == 1
    adapted = original.replace("FROM ubuntu:24.04", "FROM " + BASE, 1).replace(
        "ARG RUST_TOOLCHAIN=1.95.0", "ARG RUST_TOOLCHAIN=1.95.0\n"
        "ENV RUSTUP_TOOLCHAIN=1.95.0 CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_RELEASE_DEBUG=0", 1)
    adapted += "\n# Container-only aliases required by the unchanged canonical musl driver.\n"
    adapted += "RUN test -x /usr/bin/musl-gcc && test -d /usr/include/x86_64-linux-musl \\\n"
    adapted += "    && ln -s /usr/bin/musl-gcc /usr/local/bin/x86_64-unknown-linux-musl-gcc \\\n"
    adapted += "    && mkdir -p /usr/local/musl/x86_64-unknown-linux-musl \\\n"
    adapted += "    && ln -s /usr/include/x86_64-linux-musl /usr/local/musl/x86_64-unknown-linux-musl/include\n"
    adapted += "ENV CC_x86_64_unknown_linux_musl=musl-gcc AR_x86_64_unknown_linux_musl=ar\n"
    (image_context / "Dockerfile").write_text(adapted)
    shutil.copyfile(image_context / "Dockerfile", evidence / "Dockerfile.realized")
    receipt["adapter"] = {
        "dockerfile_sha256": sha(image_context / "Dockerfile"),
        "compiler_alias": "x86_64-unknown-linux-musl-gcc -> /usr/bin/musl-gcc",
        "include_alias": "/usr/local/musl/x86_64-unknown-linux-musl/include -> /usr/include/x86_64-linux-musl",
        "target_cc": "musl-gcc", "target_ar": "ar", "jobs": 2,
    }
    run("image-build", ["docker", "build", "--platform", "linux/amd64", "--build-arg", "RUST_TOOLCHAIN=1.95.0",
                         "--iidfile", str(output / "image-id"), str(image_context)])
    image = (output / "image-id").read_text().strip()
    inspected = json.loads(capture(["docker", "image", "inspect", image]))[0]
    assert inspected["Id"] == image and inspected["Os"] == "linux" and inspected["Architecture"] == "amd64"
    receipt["builder_image_id"] = image
    (evidence / "image-inspect.json").write_text(json.dumps(inspected, indent=2) + "\n")
    startup = run("builder-preflight", ["docker", "run", "--rm", "--network", "none", image,
        "bash", "-ceu", 'test "$(uname -m)" = x86_64; test "$(rustc --version | cut -d " " -f 2)" = 1.95.0; '
        'rustc -Vv; cargo -V; rustup target list --installed; musl-gcc --version; ld --version; '
        'readlink -f /usr/local/bin/x86_64-unknown-linux-musl-gcc; '
        'readlink -f /usr/local/musl/x86_64-unknown-linux-musl/include; dpkg-query -W'])
    assert TARGET in startup.read_text()

    build_root = output / "work"
    build_root.mkdir()
    target = output / "target"
    env = os.environ.copy()
    for name in list(env):
        if name.startswith("NVPN_"):
            del env[name]
    env.update(NVPN_LINUX_MUSL_IMAGE=image, NVPN_LINUX_MUSL_BUILD_ROOT=str(build_root),
               NVPN_LINUX_MUSL_TARGET_DIR=str(target), NVPN_LINUX_MUSL_KEEP_WORK="1",
               NVPN_FIPS_REPO_PATH=str(fips), NVPN_MARKED_EXPECTED_LOCK=str(evidence / "Cargo.lock.expected"),
               CARGO_INCREMENTAL="0", LC_ALL="C", TZ="UTC")
    original_driver = (app / "scripts/build-nvpn-linux-musl").read_text()
    assert sha(app / "scripts/build-nvpn-linux-musl") == "0b94f88c18693e87e4c3e4ee3d8e1c81d3227503c00b5d76d9b879b0672ad5cc"
    driver = evidence / "build-nvpn-linux-musl.locked"
    driver.write_text(locked_driver(original_driver))
    (evidence / "build-driver.diff").write_text("".join(difflib.unified_diff(
        original_driver.splitlines(keepends=True), driver.read_text().splitlines(keepends=True),
        fromfile="canonical", tofile="locked-diagnostic")))
    receipt["driver_adapter"] = {"sha256": sha(driver), "diff_sha256": sha(evidence / "build-driver.diff"),
        "changes": "materialize approved lock; skip three FIPS updates; locked musl/native-host fetch and frozen build"}
    run("driver-syntax", ["bash", "-n", str(driver)])
    try:
        run("daemon-build", ["bash", str(driver), TARGET], cwd=app, env=env)
    finally:
        workdirs = list(build_root.glob("nvpn-linux-musl.*"))
        if len(workdirs) == 1 and (workdirs[0] / "Cargo.lock").is_file():
            shutil.copyfile(workdirs[0] / "Cargo.lock", evidence / "Cargo.lock.realized")
            receipt["realized_lock_sha256"] = sha(workdirs[0] / "Cargo.lock")
    assert len(workdirs) == 1
    work = workdirs[0]
    run("realized-lock", ["python3", str(verifier), "--validate", str(app / "Cargo.lock"), str(work / "Cargo.lock"), *packages])
    assert sha(work / "Cargo.lock") == expected_lock
    verify_archive(work, before_app, {"Cargo.toml": hashlib.sha256(manifest.encode()).hexdigest(), "Cargo.lock": expected_lock})
    assert source(work / ".fips-patch", FIPS_SHA, FIPS_TREE) == before_fips
    assert source(app, APP_SHA, APP_TREE) == before_app
    assert source(fips, FIPS_SHA, FIPS_TREE) == before_fips
    receipt["source_before_after_match"] = True
    receipt["archive_source_verified"] = True

    cache = "nvpn-musl-" + TARGET + f"-{os.getuid()}-{os.getgid()}-" + image.removeprefix("sha256:")
    metadata = run("resolved-features", ["docker", "run", "--rm", "--network", "none", "-u", f"{os.getuid()}:{os.getgid()}",
        "-v", str(work) + ":/home/rust/src", "-v", cache + ":/tmp/nvpn-cache", "-w", "/home/rust/src",
        "-e", "CARGO_HOME=/tmp/nvpn-cache/cargo", "-e", "HOME=/home/rust/src", image,
        "cargo", "--config", 'patch.crates-io.nvpn-fips-endpoint.path="/home/rust/src/.fips-patch/crates/fips-endpoint"',
        "--config", 'patch.crates-io.nvpn-fips-core.path="/home/rust/src/.fips-patch/crates/fips-core"',
        "--config", 'patch.crates-io.nvpn-fips-identity.path="/home/rust/src/.fips-patch/crates/fips-identity"',
        "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", TARGET])
    metadata_rows = [line for line in metadata.read_text().splitlines() if line.startswith("{")]
    assert len(metadata_rows) == 1
    resolved = json.loads(metadata_rows[0])
    daemon = next(p for p in resolved["packages"] if p["name"] == "nvpn")
    features = next(n["features"] for n in resolved["resolve"]["nodes"] if n["id"] == daemon["id"])
    assert "default" in features and "paid-exit" in features
    receipt["daemon_features"] = features
    assert sha(work / "Cargo.lock") == expected_lock

    binary = target / TARGET / "release/nvpn"
    file_log = run("file", ["file", "-b", str(binary)])
    assert "ELF 64-bit" in file_log.read_text() and "x86-64" in file_log.read_text()
    program = run("elf-program-headers", ["readelf", "-lW", str(binary)])
    dynamic = run("elf-dynamic", ["readelf", "-dW", str(binary)])
    assert "INTERP" not in program.read_text() and "NEEDED" not in dynamic.read_text()
    version = run("version", ["timeout", "15", str(binary), "--version"])
    help_log = run("help", ["timeout", "15", str(binary), "--help"])
    assert "4.1.19" in version.read_text() and "Usage:" in help_log.read_text()
    verify_archive(work, before_app, {"Cargo.toml": hashlib.sha256(manifest.encode()).hexdigest(), "Cargo.lock": expected_lock})
    assert source(work / ".fips-patch", FIPS_SHA, FIPS_TREE) == before_fips
    assert source(app, APP_SHA, APP_TREE) == before_app
    assert source(fips, FIPS_SHA, FIPS_TREE) == before_fips
    (output / "binary").mkdir()
    shutil.copy2(binary, output / "binary/nvpn")
    receipt["binary"] = {"sha256": sha(binary), "bytes": binary.stat().st_size,
                         "target": TARGET, "static": True, "version": version.read_text().strip()}
    receipt["success"] = True
finally:
    receipt["seconds"] = time.monotonic() - started
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"success": receipt["success"], "seconds": receipt["seconds"]}), flush=True)
