"""Build an attribution-only daemon with one immutable core source override."""
import hashlib
import difflib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib
import tarfile
import urllib.request
from contextlib import contextmanager

APP_SHA = os.environ["APP_SOURCE_SHA"]
APP_TREE = os.environ["APP_SOURCE_TREE"]
EXPECTED_LOCK = os.environ["APP_LOCK_SHA256"]
FIPS_SHA = os.environ["FIPS_SOURCE_SHA"]
FIPS_TREE = os.environ["FIPS_SOURCE_TREE"]
FIPS_BASE = "824ed235d8422f99c51d898affb1931a83fb98ca"
CORE_NAME = "nvpn-fips-core"
CORE_DIRECTORY = ".fips-core-diagnostic"
CHANGED_CORE_FILES = ["src/node/handlers/handshake.rs", "src/node/wire.rs"]
EXPECTED_PACKAGES = {
    "nvpn-fips-core": ("0.4.109", "2baf7c1c2e6e8170b102c60ce8158b5d25ad6997e3f2de7ed5d0490ce2e16eb1"),
    "nvpn-fips-endpoint": ("0.4.109", "c6f8f1323c421f07271505516542a6b4b4e148a0663e1dbcf3525524673865c4"),
    "nvpn-fips-tcp-endpoint": ("0.2.44", "70489db5838739c619a02024906dfeb72b854e4a7f06db3fa3a2afa62a762d81"),
    "nostr-pubsub-fips": ("0.5.39", os.environ["PUBSUB_ARCHIVE_SHA256"]),
}
BASE = "ubuntu@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc"
TARGET = "x86_64-unknown-linux-musl"

app, fips, output = (Path(arg).resolve() for arg in sys.argv[1:])
assert os.uname().sysname == "Linux" and os.uname().machine == "x86_64"
assert not output.exists()
evidence = output / "evidence"
evidence.mkdir(parents=True)
started = time.monotonic()
receipt = {"success": False, "diagnostic_only": True, "registry_resolved_server_build": False,
           "runtime_acceptance": False, "cpu_acceptance": False,
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
    """Keep the canonical cache/build, with one prepared core path and lock."""
    build = 'cargo "${cargo_config_args[@]}" build "${cargo_lock_args[@]}"'
    assert original.count(build) == 1
    adapted = original.replace(build, 'cargo "${cargo_config_args[@]}" build --frozen')
    fetch = 'cargo "${cargo_config_args[@]}" fetch "${cargo_lock_args[@]}" --target "$TARGET"'
    assert adapted.count(fetch) == 1
    adapted = adapted.replace(fetch, fetch + ' --target x86_64-unknown-linux-gnu')
    anchor = 'mkdir -p "$TARGET_DIR"'
    assert adapted.count(anchor) == 1
    adapted = adapted.replace(anchor, anchor + '\n'
        'cp -R "$NVPN_DIAGNOSTIC_CORE_PATH" "$WORK_DIR/.fips-core-diagnostic"\n'
        'cp "$NVPN_DIAGNOSTIC_LOCK_PATH" "$WORK_DIR/Cargo.lock"')
    assert adapted.count('cargo_config_args=()') == 1
    adapted = adapted.replace('cargo_config_args=()',
        'cargo_config_args=(--config \'patch.crates-io.nvpn-fips-core.path="/home/rust/src/.fips-core-diagnostic"\')')
    adapted = adapted.replace('".fips-patch", ".nostr-pubsub-patch"',
                              '".fips-patch", ".fips-core-diagnostic", ".nostr-pubsub-patch"')
    return adapted


def verify_lock_override(path):
    actual = tomllib.loads(Path(path).read_text())
    expected = tomllib.loads((app / "Cargo.lock").read_text())
    core = next(p for p in expected["package"] if p["name"] == CORE_NAME)
    del core["source"]
    del core["checksum"]
    assert actual == expected, "dependency closure drift beyond core source override"


@contextmanager
def parser_workspace(root):
    """Expose core dev-dependencies only for tests; restore production inputs."""
    manifest_path, lock_path = root / "Cargo.toml", root / "Cargo.lock"
    manifest, lock = manifest_path.read_text(), lock_path.read_text()
    assert manifest.count("\nmembers = [\n") == 1
    test_manifest = manifest.replace("\nmembers = [\n", '\nmembers = [\n  ".fips-core-diagnostic",\n', 1)
    test_manifest = test_manifest.replace(', ".fips-core-diagnostic"', '')
    sections = lock.split("[[package]]")
    matches = [i for i, section in enumerate(sections) if section.startswith('\nname = "nvpn-fips-core"\n')]
    assert len(matches) == 1
    index = matches[0]
    assert ' "tempfile",\n' not in sections[index]
    assert sections[index].count(' "thiserror 2.0.18",\n') == 1
    sections[index] = sections[index].replace(' "thiserror 2.0.18",\n', ' "tempfile",\n "thiserror 2.0.18",\n')
    test_lock = "[[package]]".join(sections)
    expected = tomllib.loads(lock)
    core = next(p for p in expected["package"] if p["name"] == CORE_NAME)
    core["dependencies"] = sorted([*core["dependencies"], "tempfile"])
    assert tomllib.loads(test_lock) == expected
    try:
        manifest_path.write_text(test_manifest)
        lock_path.write_text(test_lock)
        yield
        assert manifest_path.read_text() == test_manifest
        assert lock_path.read_text() == test_lock
    finally:
        manifest_path.write_text(manifest)
        lock_path.write_text(lock)


def prepare_core():
    """Retain the published normalized manifest and every unchanged crate byte."""
    before = source(fips, FIPS_SHA, FIPS_TREE)
    assert capture(["git", "rev-parse", "HEAD^"], fips) == FIPS_BASE
    changed = capture(["git", "diff", "--name-only", FIPS_BASE, "HEAD"], fips).splitlines()
    assert sorted(changed) == sorted("crates/fips-core/" + p for p in CHANGED_CORE_FILES)
    archive = output / "nvpn-fips-core-0.4.109.crate"
    with urllib.request.urlopen("https://static.crates.io/crates/nvpn-fips-core/nvpn-fips-core-0.4.109.crate", timeout=60) as response:
        archive.write_bytes(response.read())
    assert sha(archive) == EXPECTED_PACKAGES[CORE_NAME][1]
    unpack = output / "published-core"
    unpack.mkdir()
    with tarfile.open(archive) as bundle:
        bundle.extractall(unpack, filter="data")
    core = unpack / "nvpn-fips-core-0.4.109"
    manifest = tomllib.loads((core / "Cargo.toml").read_text())
    assert manifest["package"]["name"] == CORE_NAME
    assert manifest["package"]["version"] == "0.4.109"
    assert not any("path" in dep for dep in manifest["dependencies"].values() if isinstance(dep, dict))
    published = {str(p.relative_to(core)): sha(p) for p in core.rglob("*") if p.is_file()}
    for name in published:
        if name.startswith("src/"):
            original = subprocess.check_output(["git", "show", FIPS_BASE + ":crates/fips-core/" + name], cwd=fips)
            assert hashlib.sha256(original).hexdigest() == published[name], name
    for name in CHANGED_CORE_FILES:
        shutil.copyfile(fips / "crates/fips-core" / name, core / name)
    realized = {str(p.relative_to(core)): sha(p) for p in core.rglob("*") if p.is_file()}
    assert sorted(name for name in realized if realized[name] != published[name]) == sorted(CHANGED_CORE_FILES)
    diff = subprocess.check_output(["git", "diff", "--binary", FIPS_BASE, "HEAD"], cwd=fips)
    (evidence / "core-source.diff").write_bytes(diff)
    (evidence / "core-files.json").write_text(json.dumps(realized, indent=2) + "\n")
    receipt["core_override"] = {"sha": FIPS_SHA, "tree": FIPS_TREE, "base_sha": FIPS_BASE,
        "published_archive_sha256": sha(archive), "changed_files": CHANGED_CORE_FILES,
        "source_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "normalized_manifest_sha256": sha(core / "Cargo.toml"), "files_sha256": realized,
        "header_index_is_untrusted": True, "policy_changed": False}
    assert source(fips, FIPS_SHA, FIPS_TREE) == before
    return core


try:
    before_app = source(app, APP_SHA, APP_TREE)
    receipt["inputs"] = {
        "app_sha": APP_SHA, "app_tree": APP_TREE, "app_files_sha256": fingerprint(before_app),
        "canonical_wrapper_sha256": sha(app / "scripts/build-nvpn-linux-musl"),
        "base_dockerfile_sha256": sha(app / "Dockerfile.linux-vm-gate"),
        "helper_sha256": sha(__file__),
        "workflow_sha256": sha(Path(__file__).resolve().parents[1] / ".github/workflows/marked-seed-daemon.yml"),
    }
    disk = os.statvfs(output)
    receipt["resources_before"] = {"disk_available_bytes": disk.f_bavail * disk.f_frsize,
                                   "meminfo": Path("/proc/meminfo").read_text()}
    memory = dict(line.split(":", 1) for line in receipt["resources_before"]["meminfo"].splitlines())
    assert receipt["resources_before"]["disk_available_bytes"] >= 14 * 1024 ** 3
    assert int(memory["MemAvailable"].split()[0]) >= 3 * 1024 ** 2
    assert sha(app / "Cargo.lock") == EXPECTED_LOCK
    lock = tomllib.loads((app / "Cargo.lock").read_text())
    for name, (version, checksum) in EXPECTED_PACKAGES.items():
        matches = [p for p in lock["package"] if p["name"] == name]
        assert len(matches) == 1
        assert matches[0]["version"] == version and matches[0]["checksum"] == checksum
        assert matches[0]["source"] == "registry+https://github.com/rust-lang/crates.io-index"
    receipt["registry_packages"] = EXPECTED_PACKAGES
    receipt["expected_lock_sha256"] = EXPECTED_LOCK
    shutil.copyfile(app / "Cargo.lock", evidence / "Cargo.lock.committed")
    core = prepare_core()

    # Resolve the committed registry lock before the expensive image/build steps.
    run("resolver-toolchain", ["rustup", "toolchain", "install", "1.95.0", "--profile", "minimal"])
    run("resolver-version", ["cargo", "+1.95.0", "--version", "--verbose"])
    preflight = output / "lock-preflight"
    preflight.mkdir()
    archive = output / "app.tar"
    subprocess.run(["git", "archive", "--format=tar", "--output=" + str(archive), "HEAD"], cwd=app, check=True)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(preflight)], check=True)
    shutil.copytree(core, preflight / CORE_DIRECTORY)
    lock_text = (app / "Cargo.lock").read_text()
    checksum = EXPECTED_PACKAGES[CORE_NAME][1]
    old = 'name = "nvpn-fips-core"\nversion = "0.4.109"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + checksum + '"\n'
    assert lock_text.count(old) == 1
    (preflight / "Cargo.lock").write_text(lock_text.replace(old, 'name = "nvpn-fips-core"\nversion = "0.4.109"\n'))
    verify_lock_override(preflight / "Cargo.lock")
    run("resolve-locked", ["cargo", "+1.95.0", "--config",
                           'patch.crates-io.nvpn-fips-core.path=".fips-core-diagnostic"',
                           "metadata", "--locked", "--format-version", "1",
                           "--filter-platform", TARGET], cwd=preflight)
    shutil.copyfile(preflight / "Cargo.lock", evidence / "Cargo.lock.preflight")
    receipt["preflight_lock_sha256"] = sha(preflight / "Cargo.lock")
    verify_lock_override(preflight / "Cargo.lock")
    diagnostic_lock = sha(preflight / "Cargo.lock")
    verify_archive(preflight, before_app, {"Cargo.lock": diagnostic_lock})
    with parser_workspace(preflight):
        test_metadata = run("parser-workspace-preflight", ["cargo", "+1.95.0", "--config",
            'patch.crates-io.nvpn-fips-core.path=".fips-core-diagnostic"', "metadata", "--locked",
            "--format-version", "1", "--filter-platform", TARGET], cwd=preflight)
        parsed = json.loads(test_metadata.read_text().splitlines()[-1])
        package = next(p for p in parsed["packages"] if p["name"] == CORE_NAME)
        assert package["id"] in parsed["workspace_members"]
        shutil.copyfile(preflight / "Cargo.lock", evidence / "Cargo.lock.parser-tests")
        receipt["parser_workspace"] = {"lock_sha256": sha(preflight / "Cargo.lock"),
            "manifest_sha256": sha(preflight / "Cargo.toml"),
            "only_added_dependency_edge": "nvpn-fips-core -> tempfile (existing locked version)"}
    assert sha(preflight / "Cargo.lock") == diagnostic_lock
    verify_archive(preflight, before_app, {"Cargo.lock": diagnostic_lock})
    assert source(app, APP_SHA, APP_TREE) == before_app

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

    cache = "nvpn-musl-" + TARGET + f"-{os.getuid()}-{os.getgid()}-" + image.removeprefix("sha256:")
    test_container = ["docker", "run", "--rm", "--network", "none", "-u", f"{os.getuid()}:{os.getgid()}",
        "-v", str(preflight) + ":/home/rust/src", "-v", cache + ":/tmp/nvpn-cache", "-w", "/home/rust/src",
        "-e", "CARGO_HOME=/tmp/nvpn-cache/cargo", "-e", "CARGO_TARGET_DIR=/tmp/nvpn-cache/target",
        "-e", "HOME=/home/rust/src",
        "-e", "SOURCE_DATE_EPOCH=" + capture(["git", "show", "-s", "--format=%ct", "HEAD"], app),
        "-e", "ZERO_AR_DATE=1", "-e", "LC_ALL=C", "-e", "TZ=UTC",
        "-e", "BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_linux_musl=-I/usr/local/musl/x86_64-unknown-linux-musl/include",
        "-e", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-unknown-linux-musl-gcc", image]
    run("cache-init", ["docker", "run", "--rm", "--network", "none", "-u", "0",
        "-v", cache + ":/tmp/nvpn-cache", "--entrypoint", "chown", image,
        f"{os.getuid()}:{os.getgid()}", "/tmp/nvpn-cache"])
    config = ['--config', 'patch.crates-io.nvpn-fips-core.path="/home/rust/src/.fips-core-diagnostic"']
    with parser_workspace(preflight):
        assert sha(preflight / "Cargo.lock") == receipt["parser_workspace"]["lock_sha256"]
        fetch_container = test_container.copy()
        fetch_container[fetch_container.index("--network") + 1] = "bridge"
        run("parser-fetch", fetch_container + ["flock", "/tmp/nvpn-cache/build.lock", "cargo", *config,
            "fetch", "--locked", "--target", TARGET, "--target", "x86_64-unknown-linux-gnu"])
        tests = run("msg1-header-tests", test_container + ["flock", "/tmp/nvpn-cache/build.lock", "cargo", *config,
            "test", "--frozen", "-p", CORE_NAME, "--lib", "--release", "--target", TARGET,
            "node::wire::tests::test_msg1_header", "--", "--nocapture"])
    assert "7 passed; 0 failed; 0 ignored;" in tests.read_text()
    receipt["parser_tests"] = {"passed": 7, "failed": 0, "ignored": 0}
    verify_lock_override(preflight / "Cargo.lock")
    verify_archive(preflight, before_app, {"Cargo.lock": diagnostic_lock})

    build_root = output / "work"
    build_root.mkdir()
    target = output / "target"
    env = os.environ.copy()
    for name in list(env):
        if name.startswith("NVPN_"):
            del env[name]
    env.update(NVPN_LINUX_MUSL_IMAGE=image, NVPN_LINUX_MUSL_BUILD_ROOT=str(build_root),
               NVPN_LINUX_MUSL_TARGET_DIR=str(target), NVPN_LINUX_MUSL_KEEP_WORK="1",
               NVPN_DIAGNOSTIC_CORE_PATH=str(core), NVPN_DIAGNOSTIC_LOCK_PATH=str(preflight / "Cargo.lock"),
               CARGO_INCREMENTAL="0", LC_ALL="C", TZ="UTC")
    original_driver = (app / "scripts/build-nvpn-linux-musl").read_text()
    assert sha(app / "scripts/build-nvpn-linux-musl") == "0b94f88c18693e87e4c3e4ee3d8e1c81d3227503c00b5d76d9b879b0672ad5cc"
    driver = evidence / "build-nvpn-linux-musl.locked"
    driver.write_text(locked_driver(original_driver))
    (evidence / "build-driver.diff").write_text("".join(difflib.unified_diff(
        original_driver.splitlines(keepends=True), driver.read_text().splitlines(keepends=True),
        fromfile="canonical", tofile="locked-registry")))
    receipt["driver_adapter"] = {"sha256": sha(driver), "diff_sha256": sha(evidence / "build-driver.diff"),
        "changes": "locked musl/native-host fetch and frozen build; immutable prepared core-only override"}
    run("driver-syntax", ["bash", "-n", str(driver)])
    try:
        run("daemon-build", ["bash", str(driver), TARGET], cwd=app, env=env)
        # Preserve the completed default-feature ELF outside the shared Cargo target.
        built_binary = target / TARGET / "release/nvpn"
        (output / "binary").mkdir()
        binary = output / "binary/nvpn"
        shutil.copy2(built_binary, binary)
        default_binary_sha = sha(binary)
        receipt["built_binary_unqualified"] = {"sha256": default_binary_sha,
            "bytes": binary.stat().st_size, "target": TARGET,
            "app_sha": APP_SHA, "core_sha": FIPS_SHA, "qualified": False}

    finally:
        workdirs = list(build_root.glob("nvpn-linux-musl.*"))
        if len(workdirs) == 1 and (workdirs[0] / "Cargo.lock").is_file():
            shutil.copyfile(workdirs[0] / "Cargo.lock", evidence / "Cargo.lock.realized")
            receipt["realized_lock_sha256"] = sha(workdirs[0] / "Cargo.lock")
    assert len(workdirs) == 1
    work = workdirs[0]
    assert sha(work / "Cargo.lock") == diagnostic_lock
    verify_lock_override(work / "Cargo.lock")
    manifest = (app / "Cargo.toml").read_text().replace(
        'exclude = ["linux"]',
        'exclude = ["linux", ".fips-patch", ".fips-core-diagnostic", ".nostr-pubsub-patch", ".cashu-service-patch", "cashu_spilman_channels"]')
    exceptions = {"Cargo.toml": hashlib.sha256(manifest.encode()).hexdigest(), "Cargo.lock": diagnostic_lock}
    assert not any((work / name).exists() for name in
                   (".fips-patch", ".nostr-pubsub-patch", ".cashu-service-patch", "cashu_spilman_channels"))
    verify_archive(work, before_app, exceptions)
    for name, expected in receipt["core_override"]["files_sha256"].items():
        assert sha(work / CORE_DIRECTORY / name) == expected
    assert source(app, APP_SHA, APP_TREE) == before_app
    receipt["source_before_after_match"] = True
    receipt["archive_source_verified"] = True

    container = test_container.copy()
    container[container.index(str(preflight) + ":/home/rust/src")] = str(work) + ":/home/rust/src"
    metadata = run("resolved-features", container + [
        "cargo", *config, "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", TARGET])
    metadata_rows = [line for line in metadata.read_text().splitlines() if line.startswith("{")]
    assert len(metadata_rows) == 1
    resolved = json.loads(metadata_rows[0])
    daemon = next(p for p in resolved["packages"] if p["name"] == "nvpn")
    features = next(n["features"] for n in resolved["resolve"]["nodes"] if n["id"] == daemon["id"])
    assert set(features) == {"default", "paid-exit"}
    for name, (expected_version, _) in EXPECTED_PACKAGES.items():
        packages = [p for p in resolved["packages"] if p["name"] == name]
        assert len(packages) == 1
        assert packages[0]["version"] == expected_version
        assert packages[0]["source"] == (None if name == CORE_NAME else "registry+https://github.com/rust-lang/crates.io-index")
    receipt["daemon_features"] = features
    assert sha(work / "Cargo.lock") == diagnostic_lock
    verify_lock_override(work / "Cargo.lock")

    assert sha(binary) == default_binary_sha
    assert sha(built_binary) == default_binary_sha
    file_log = run("file", ["file", "-b", str(binary)])
    assert "ELF 64-bit" in file_log.read_text() and "x86-64" in file_log.read_text()
    program = run("elf-program-headers", ["readelf", "-lW", str(binary)])
    dynamic = run("elf-dynamic", ["readelf", "-dW", str(binary)])
    assert "INTERP" not in program.read_text() and "NEEDED" not in dynamic.read_text()
    version = run("version", ["timeout", "15", str(binary), "--version"])
    help_log = run("help", ["timeout", "15", str(binary), "--help"])
    assert "4.1.19" in version.read_text() and "Usage:" in help_log.read_text()
    verify_archive(work, before_app, exceptions)
    assert source(app, APP_SHA, APP_TREE) == before_app
    receipt["binary"] = {"sha256": sha(binary), "bytes": binary.stat().st_size,
                         "target": TARGET, "static": True, "version": version.read_text().strip()}
    receipt["success"] = True
finally:
    receipt["seconds"] = time.monotonic() - started
    (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"success": receipt["success"], "seconds": receipt["seconds"]}), flush=True)
