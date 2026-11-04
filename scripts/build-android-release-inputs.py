#!/usr/bin/env python3
"""Qualify inputs and build the frozen unsigned Android bundle on a hosted runner.

No signing credentials, device operations or release acceptance belong here.
The first phase only reads installed tools and their identities.
"""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

PINS = Path(__file__).with_name("android-release-inputs.json")
SIGNING_VARIABLES = (
    "ANDROID_KEYSTORE_PATH", "ANDROID_KEYSTORE_PASSWORD", "ANDROID_KEY_ALIAS",
    "ANDROID_KEY_PASSWORD", "ANDROID_KEYSTORE_B64",
)


def require(value, message):
    if not value:
        raise ValueError(message)


def unsigned_environment(environment):
    require(not any(environment.get(key) for key in SIGNING_VARIABLES),
            "Hosted Android compilation must not receive signing credentials")


def required_free_bytes(capacity):
    require(capacity["physicalFloorBytes"] >= 20 * 1024**3,
            "The physical reserve must remain at least 20 GiB")
    values = [capacity[key] for key in (
        "physicalFloorBytes", "maximumOwnGrowthBudgetBytes", "concurrentGrowthBudgetBytes")]
    require(all(isinstance(value, int) and value >= 0 for value in values), "Invalid capacity budget")
    return sum(values)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def capture(*arguments, env=None):
    completed = subprocess.run(arguments, capture_output=True, text=True, timeout=30, env=env)
    require(completed.returncode == 0, "Native tool failed: " + Path(arguments[0]).name + ": " +
            (completed.stdout + completed.stderr)[-1200:])
    return (completed.stdout + completed.stderr).strip()


def properties(path):
    if not path.is_file():
        return {}
    return {key.strip(): value.strip().strip('"')
            for line in path.read_text(errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#") and "=" in line
            for key, value in [line.split("=", 1)]}


def memory():
    result = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith(("MemTotal:", "MemAvailable:")):
            name, amount, unit = line.split()
            require(unit == "kB", "Unexpected memory unit")
            result[name.rstrip(":") + "Bytes"] = int(amount) * 1024
    return result


def sdk_inventory(sdk, pins):
    result = {"packages": {}, "ndk": None}
    for category in ("platforms", "build-tools", "ndk", "cmdline-tools"):
        root = sdk / category
        result["packages"][category] = {
            child.name: properties(child / "source.properties")
            for child in sorted(root.iterdir()) if child.is_dir()
        } if root.is_dir() else {}
    ndk = sdk / "ndk" / pins["ndkVersion"]
    clang = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
    if clang.is_file():
        result["ndk"] = {
            "properties": properties(ndk / "source.properties"),
            "clangSha256": digest(clang),
            "clangVersion": capture(str(clang), "--version").splitlines()[:2],
        }
    result["buildToolHashes"] = {}
    for version in result["packages"]["build-tools"]:
        directory = sdk / "build-tools" / version
        result["buildToolHashes"][version] = {
            name: digest(directory / name)
            for name in ("aapt2", "zipalign", "apksigner", "lib/apksigner.jar")
            if (directory / name).is_file()
        }
    return result


def java_inventory():
    candidates = []
    for variable in ("JAVA_HOME_17_X64", "JAVA_HOME"):
        value = os.environ.get(variable)
        if value and Path(value).resolve() not in candidates:
            candidates.append(Path(value).resolve())
    results = []
    for root in candidates:
        release = properties(root / "release")
        if not release.get("JAVA_VERSION", "").startswith("17."):
            continue
        results.append({
            "release": {name: release.get(name) for name in
                        ("JAVA_VERSION", "JAVA_RUNTIME_VERSION", "IMPLEMENTOR", "OS_ARCH", "MODULES")},
            "version": [line for line in capture(str(root / "bin/java"), "-version").splitlines()
                        if not line.startswith("Picked up ")],
            "files": {name: digest(root / name) for name in
                      ("bin/java", "bin/javac", "bin/jarsigner", "lib/modules") if (root / name).is_file()},
        })
    return results


def inventory(output, pins):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Expected the established hosted Linux x86_64 Android route")
    require(os.environ.get("GITHUB_ACTIONS") == "true", "This inventory runs on the hosted producer")
    require(not output.exists(), "Inventory output must be new")
    output.mkdir()
    available = shutil.disk_usage(output).free
    sdk = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or "/nonexistent")
    require(sdk.is_dir(), "The hosted Android SDK is unavailable")
    value = {
        "schema": 1,
        "scope": "Read-only native tool and capacity inventory; no compilation or signing",
        "producerCommit": os.environ.get("GITHUB_SHA"),
        "runId": os.environ.get("GITHUB_RUN_ID"),
        "imageVersion": os.environ.get("ImageVersion"),
        "imageOS": os.environ.get("ImageOS"),
        "os": {key: val for key, val in properties(Path("/etc/os-release")).items()
               if key in ("ID", "VERSION_ID", "PRETTY_NAME")},
        "cpuCount": os.cpu_count(), "memory": memory(),
        "freeBytes": available, "requiredBuildEntryBytes": required_free_bytes(pins["capacity"]),
        "capacity": pins["capacity"], "sdk": sdk_inventory(sdk, pins), "java": java_inventory(),
        "compiled": False, "signed": False, "buildAdmitted": False,
    }
    (output / "inventory.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value[key] for key in
                      ("imageVersion", "freeBytes", "requiredBuildEntryBytes", "cpuCount", "memory", "compiled")}))


def qualify_ndk(output, pins):
    require(os.environ.get("GITHUB_ACTIONS") == "true" and platform.system() == "Linux",
            "NDK input qualification runs on the hosted producer")
    require(not output.exists(), "Qualification output must be new")
    output.mkdir()
    initial_free = shutil.disk_usage(output).free
    require(initial_free >= required_free_bytes(pins["capacity"]),
            "20 GiB reserve plus the declared growth budget is unavailable")
    archive_pin = pins["ndkArchive"]
    minimum_free = initial_free
    with tempfile.TemporaryDirectory(prefix="ndk-input-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        archive = Path(temporary) / "ndk.zip"
        sha1, sha256, total = hashlib.sha1(), hashlib.sha256(), 0
        with urllib.request.urlopen(archive_pin["url"], timeout=60) as response, archive.open("xb") as target:
            require(response.geturl().startswith("https://"), "NDK download left HTTPS")
            while block := response.read(1024 * 1024):
                total += len(block)
                require(total <= archive_pin["size"], "NDK archive exceeded the published size")
                minimum_free = min(minimum_free, shutil.disk_usage(output).free)
                require(minimum_free >= pins["capacity"]["physicalFloorBytes"] + 1024**3,
                        "NDK download reached the reserve abort margin")
                target.write(block)
                sha1.update(block)
                sha256.update(block)
        require(total == archive_pin["size"] and sha1.hexdigest() == archive_pin["publishedSha1"],
                "NDK archive differs from Android's published r28c identity")
        with zipfile.ZipFile(archive) as package:
            properties_bytes = package.read("android-ndk-r28c/source.properties")
            require(b"Pkg.Revision = 28.2.13676358" in properties_bytes, "NDK package revision differs")
            expanded_bytes = sum(entry.file_size for entry in package.infolist())
            clang_name = "android-ndk-r28c/toolchains/llvm/prebuilt/linux-x86_64/bin/clang-19"
            with package.open(clang_name) as stream:
                clang_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        sdk = Path(os.environ.get("ANDROID_HOME") or os.environ["ANDROID_SDK_ROOT"])
        sdk_files = {}
        for name in ("android.jar", "core-for-system-modules.jar", "framework.aidl"):
            path = sdk / "platforms/android-36" / name
            if path.is_file():
                sdk_files[name] = digest(path)
        record = {"schema": 1, "source": archive_pin, "size": total,
                  "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(),
                  "expandedBytes": expanded_bytes, "clangSha256": clang_hash,
                  "sourcePropertiesSha256": hashlib.sha256(properties_bytes).hexdigest(),
                  "sdk36Files": sdk_files,
                  "initialFreeBytes": initial_free, "minimumFreeBytes": minimum_free,
                  "extracted": False, "executed": False, "compiled": False,
                  "producerCommit": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"]}
        (output / "ndk-qualification.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(json.dumps({key: record[key] for key in
                          ("sha256", "expandedBytes", "minimumFreeBytes", "executed", "compiled")}))


def verification_xml(pins):
    """Use Gradle's verifier before any downloaded plugin/dependency is loaded."""
    root = ET.Element("verification-metadata", xmlns="https://schema.gradle.org/dependency-verification")
    config = ET.SubElement(root, "configuration")
    ET.SubElement(config, "verify-metadata").text = "true"
    ET.SubElement(config, "verify-signatures").text = "false"
    components = ET.SubElement(root, "components")
    seen = set()
    for item in pins["gradleVerification"]["components"]:
        component = ET.SubElement(components, "component", {
            "group": item["group"], "name": item["name"], "version": item["version"]})
        for artifact in item["artifacts"]:
            key = (item["group"], item["name"], item["version"], artifact["name"])
            require(key not in seen, "Dependency artifact has ambiguous checksum entries")
            seen.add(key)
            require(len(artifact["sha256"]) == 64 and all(c in "0123456789abcdef" for c in artifact["sha256"]),
                    "Dependency artifact lacks an exact SHA256")
            entry = ET.SubElement(component, "artifact", name=artifact["name"])
            ET.SubElement(entry, "sha256", value=artifact["sha256"])
    ET.indent(root)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class BuildSession:
    """Bound all producer writes/child processes on one exclusive hosted runner."""
    def __init__(self, output, pins):
        self.output, self.pins = output, pins
        self.started = time.monotonic()
        self.initial_free = shutil.disk_usage(output).free
        require(self.initial_free >= required_free_bytes(pins["capacity"]),
                "20 GiB physical floor plus own/concurrent growth is unavailable")
        self.minimum_free = self.initial_free
        self.minimum_memory = memory()["MemAvailableBytes"]
        self.commands = []
        self.abort_reason = None

    def guard(self):
        self.minimum_free = min(self.minimum_free, shutil.disk_usage(self.output).free)
        self.minimum_memory = min(self.minimum_memory, memory()["MemAvailableBytes"])
        capacity = self.pins["capacity"]
        reason = None
        if self.minimum_free < capacity["physicalFloorBytes"] + 1024**3:
            reason = "physical reserve reached its 1 GiB abort margin"
        elif self.initial_free - self.minimum_free > capacity["maximumOwnGrowthBudgetBytes"]:
            reason = "declared own growth budget exceeded"
        elif self.minimum_memory < 1024**3:
            reason = "available memory fell below 1 GiB"
        elif time.monotonic() - self.started > 5400:
            reason = "90 minute producer deadline"
        if reason:
            self.abort_reason = reason
            raise ValueError(reason)

    def run(self, args, cwd=None, env=None, stdout_path=None):
        self.guard()
        entry = {"argv": [str(arg) for arg in args], "exitCode": None}
        self.commands.append(entry)
        print("Producer command:", Path(str(args[0])).name, flush=True)
        with ExitStack() as stack:
            log = stack.enter_context((self.output / "build.log").open("a"))
            destination = stack.enter_context(stdout_path.open("xb")) if stdout_path else log
            child = subprocess.Popen(args, cwd=cwd, env=env, stdout=destination,
                                     stderr=log, start_new_session=True)
            try:
                while child.poll() is None:
                    self.guard()
                    time.sleep(2)
            except BaseException:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                raise
            finally:
                entry["exitCode"] = child.wait()
        require(entry["exitCode"] == 0, "Producer command failed; see original build.log")

    def download(self, pin, target):
        require(len(pin["sha256"]) == 64, "Download must have a reviewed SHA256 before use")
        with urllib.request.urlopen(pin["url"], timeout=60) as response, target.open("xb") as stream:
            while block := response.read(1024 * 1024):
                self.guard()
                stream.write(block)
        require(digest(target) == pin["sha256"], "Downloaded input checksum differs")
        return target

    def save_resources(self):
        self.guard_if_possible()
        value = {"capacity": self.pins["capacity"], "initialFreeBytes": self.initial_free,
                 "minimumFreeBytes": self.minimum_free, "minimumAvailableMemoryBytes": self.minimum_memory,
                 "maximumObservedVolumeGrowthBytes": self.initial_free - self.minimum_free,
                 "elapsedSeconds": round(time.monotonic() - self.started, 1),
                 "abortReason": self.abort_reason, "commands": self.commands}
        (self.output / "resources.json").write_text(json.dumps(value, indent=2) + "\n")

    def guard_if_possible(self):
        try:
            self.guard()
        except ValueError:
            pass


def exact_source(root, expected):
    actual = {"commit": capture("git", "-C", str(root), "rev-parse", "HEAD"),
              "tree": capture("git", "-C", str(root), "rev-parse", "HEAD^{tree}")}
    require(actual == {key: expected[key] for key in actual}, "Frozen source identity differs")
    require(not capture("git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"),
            "Frozen source must start clean")
    return actual


def native_environment(pins):
    qualified = pins["nativeInputs"]
    require(os.environ.get("ImageOS") == qualified["imageOS"], "Unqualified hosted OS")
    java = Path(os.environ["JAVA_HOME_17_X64"]).resolve()
    sdk = Path(os.environ.get("ANDROID_HOME") or os.environ["ANDROID_SDK_ROOT"]).resolve()
    for name, expected in qualified["java"]["files"].items():
        require(digest(java / name) == expected, "Qualified Java component differs: " + name)
    require(properties(java / "release").get("JAVA_RUNTIME_VERSION") == "17.0.21+9",
            "Qualified Java runtime differs")
    require(properties(sdk / "platforms/android-36/source.properties") == qualified["sdk36Properties"],
            "Qualified Android SDK properties differ")
    for name, expected in qualified["sdk36Files"].items():
        require(digest(sdk / "platforms/android-36" / name) == expected, "SDK file differs: " + name)
    for version, entry in qualified["buildTools"].items():
        directory = sdk / "build-tools" / version
        require(properties(directory / "source.properties") == entry["properties"],
                "Build tools revision differs")
        for name, expected in entry["files"].items():
            require(digest(directory / name) == expected, "Build tools component differs")
    require(not list((Path.home() / ".gradle/wrapper/dists").glob("**/bin/gradle")),
            "Canonical Gradle discovery would select an unqualified cached wrapper")
    return java, sdk


def install_tools(session, tools, pins, java):
    tools.mkdir()
    env = dict(os.environ, JAVA_HOME=str(java), CARGO_HOME=str(tools / "cargo-home"),
               CARGO_TARGET_DIR=str(tools / "helper-target"), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0")
    env.pop("RUSTUP_TOOLCHAIN", None)
    prefix = tools / "rust"
    env["PATH"] = os.pathsep.join([str(prefix / "bin"), str(tools / "cargo-ndk/bin"),
                                   str(tools / "gradle-8.14.3/bin"), str(java / "bin"), env["PATH"]])
    for component in pins["rustComponents"]:
        archive = session.download(component, tools / (component["name"] + ".tar.xz"))
        destination = tools / component["name"]
        destination.mkdir()
        session.run(["tar", "-xf", str(archive), "--strip-components=1", "-C", str(destination)])
        session.run(["sh", str(destination / "install.sh"), "--prefix=" + str(prefix), "--disable-ldconfig"])
        shutil.rmtree(destination)
        archive.unlink()
    require(capture(str(prefix / "bin/rustc"), "--version") == "rustc 1.95.0 (59807616e 2026-04-14)",
            "Pinned Rust distribution version differs")
    gradle = session.download(pins["gradle"], tools / "gradle.zip")
    session.run(["unzip", "-q", str(gradle), "-d", str(tools)])
    gradle.unlink()
    ndk = session.download(pins["ndkArchive"], tools / "ndk.zip")
    session.run(["unzip", "-q", str(ndk), "-d", str(tools)])
    ndk.unlink()
    ndk_root = tools / "android-ndk-r28c"
    require(digest(ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang-19") ==
            pins["ndkArchive"]["clangSha256"], "Extracted NDK compiler differs")
    require(digest(ndk_root / "source.properties") == pins["ndkArchive"]["sourcePropertiesSha256"],
            "Extracted NDK revision differs")
    env.update(ANDROID_NDK_HOME=str(ndk_root), ANDROID_NDK_ROOT=str(ndk_root), NDK_HOME=str(ndk_root),
               GRADLE_USER_HOME=str(tools / "gradle-home"))
    crate = session.download(pins["cargoNdk"], tools / "cargo-ndk.crate")
    session.run(["tar", "-xf", str(crate), "-C", str(tools)])
    session.run([str(prefix / "bin/cargo"), "install", "--locked", "--path", str(tools / "cargo-ndk-4.1.2"),
                 "--root", str(tools / "cargo-ndk")], env=env)
    require(capture(str(tools / "cargo-ndk/bin/cargo-ndk"), "ndk", "--version",
                    env=dict(env, CARGO=str(prefix / "bin/cargo"))) == "cargo-ndk 4.1.2",
            "Pinned Cargo NDK helper differs")
    return env


BUILD_SCRIPT = r'''set -euo pipefail
source scripts/release_common.sh
source scripts/local-fips-workspace.sh
enable_deterministic_build_env "$PWD"
resolve_shared_build_metadata "$PWD"
export CARGO_ENCODED_RUSTFLAGS="$(release_encoded_rustflags "$PWD")"
nvpn_prepare_local_fips_workspace "$PWD"
nvpn_verify_local_fips_metadata "$PWD" "$NVPN_ANDROID_FIPS_METADATA_RECEIPT"
nvpn_force_rebuild_local_fips_target "$PWD" aarch64-linux-android release "$NVPN_ANDROID_FIPS_REBUILD_MARKER"
python3 - <<'PY'
import json,os
from pathlib import Path
keys=('CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','SOURCE_DATE_EPOCH',
      'NVPN_BUILD_GIT_SHA','NVPN_BUILD_TIMESTAMP_UTC','ANDROID_NDK_HOME','ANDROID_NDK_ROOT','NDK_HOME')
Path(os.environ['NVPN_HOSTED_ENV_RECEIPT']).write_text(json.dumps({key:os.environ.get(key) for key in keys},indent=2)+'\n')
PY
tools/run-android :app:bundleRelease --no-daemon --max-workers=2 --dependency-verification=strict -Pandroid.builder.sdkDownload=false
'''


def file_record(path):
    return {"sha256": digest(path), "size": path.stat().st_size,
            "originalMtimeNs": path.stat().st_mtime_ns}


def bundle_native_entries(package, abi):
    names = package.namelist()
    require(len(names) == len(set(names)), "Bundle contains duplicate entries")
    require(not any(name.startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
                    for name in names), "Hosted bundle unexpectedly contains signing material")
    result = []
    for name in names:
        if name.startswith("base/lib/") and name.endswith(".so"):
            parts = name.split("/")
            require(len(parts) == 4 and parts[2] == abi and parts[3] not in (".", ".."),
                    "Unexpected JNI ABI/path")
            result.append(name)
    require("base/lib/" + abi + "/libnostr_vpn_app_core.so" in result, "Compiled application JNI is missing")
    return result


def export_bundle(app, fips, output, pins, session, env, tools):
    aab = app / "android/app/build/outputs/bundle/release/app-release.aab"
    marker = output / "provenance/forced-rebuild.marker"
    linkage = json.loads((output / "provenance/fips-linkage.json").read_text())
    checkout_hash = hashlib.sha256(str(fips).encode()).hexdigest()
    require(linkage["checkoutPathSha256"] == checkout_hash and linkage["checkoutHead"] == pins["fips"]["commit"]
            and linkage["checkoutTree"] == pins["fips"]["tree"] and linkage["fipsCoreVersion"] == pins["fips"]["version"],
            "Original hosted FIPS linkage differs")
    require(aab.stat().st_mtime_ns >= marker.stat().st_mtime_ns, "Bundle predates forced rebuild")
    unsigned = output / "unsigned"
    unsigned.mkdir()
    shutil.copy2(aab, unsigned / "app-release.aab")
    payloads = {}
    with zipfile.ZipFile(aab) as package:
        for name in bundle_native_entries(package, pins["abi"]):
            abi, library = name.split("/")[2:]
            destination = unsigned / "jni" / abi / library
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(package.read(name))
            payloads[name] = {"sha256": digest(destination), "size": destination.stat().st_size,
                              "origin": "unsigned AAB entry", "zipDateTime": package.getinfo(name).date_time}
    compiled = app / "android/app/src/main/jniLibs/arm64-v8a/libnostr_vpn_app_core.so"
    require(digest(compiled) == payloads["base/lib/arm64-v8a/libnostr_vpn_app_core.so"]["sha256"],
            "Packaged JNI does not match the freshly compiled library")
    require(compiled.stat().st_mtime_ns >= marker.stat().st_mtime_ns, "JNI predates forced rebuild")
    dep_files = sorted((app / "target/aarch64-linux-android/release/deps").glob("*fips_core-*.d"))
    require(dep_files, "Original FIPS dependency evidence is missing")
    for dep in dep_files:
        require(str(fips / "crates/fips-core") in dep.read_text(), "FIPS dependency was not compiled from the checkout")
        require(dep.stat().st_mtime_ns >= marker.stat().st_mtime_ns, "FIPS dependency predates forced rebuild")
        destination = output / "provenance/dep-info" / dep.name
        destination.parent.mkdir(exist_ok=True)
        shutil.copy2(dep, destination)
    bundletool = session.download(pins["bundletool"], tools / "bundletool.jar")
    session.run([str(Path(env["JAVA_HOME"]) / "bin/java"), "-jar", str(bundletool), "validate", "--bundle=" + str(aab)], env=env)
    manifest = subprocess.check_output([str(Path(env["JAVA_HOME"]) / "bin/java"), "-jar", str(bundletool),
                                        "dump", "manifest", "--bundle=" + str(aab)], env=env, timeout=60)
    (output / "provenance/bundle-manifest.xml").write_bytes(manifest)
    element = ET.fromstring(manifest)
    android = "{http://schemas.android.com/apk/res/android}"
    require(element.get("package") == "fi.siriusbusiness.nvpn" and element.get(android + "versionName") == "4.1.21"
            and element.get(android + "versionCode") == "4012100", "Bundle product version/package differs")
    return {"jniPayloads": payloads, "compiledJni": file_record(compiled),
            "fipsCheckoutPathSha256": checkout_hash, "forcedRebuild": file_record(marker)}


def build(output, pins, app, fips):
    require(os.environ.get("GITHUB_ACTIONS") == "true" and platform.system() == "Linux"
            and platform.machine() == "x86_64", "Unsigned producer requires the qualified hosted Linux route")
    require(not output.exists() and pins["hostedNativeComponentsQualified"], "Build output/input admission differs")
    output.mkdir()
    provenance = output / "provenance"
    provenance.mkdir()
    shutil.copy2(PINS, provenance / "inputs.json")
    session = BuildSession(output, pins)
    committed_lock = None
    try:
        identities = {"app": exact_source(app, pins["app"]), "fips": exact_source(fips, pins["fips"])}
        java, sdk = native_environment(pins)
        tools = Path(os.environ["RUNNER_TEMP"]) / "android-qualified-tools"
        env = install_tools(session, tools, pins, java)
        committed_lock = (app / "Cargo.lock").read_bytes()
        (provenance / "committed-Cargo.lock").write_bytes(committed_lock)
        specs = capture("python3", str(app / "scripts/verify-cargo-path-patch-lock.py"), "--manifest-specs", str(fips)).splitlines()
        session.run(["python3", str(app / "scripts/verify-cargo-path-patch-lock.py"), "--materialize",
                     str(app / "Cargo.lock"), str(provenance / "realized-Cargo.lock"), *specs])
        require(digest(provenance / "realized-Cargo.lock") == pins["realizedCargoLockSha256"], "Realized Cargo graph differs")
        (app / "Cargo.lock").write_bytes((provenance / "realized-Cargo.lock").read_bytes())
        verification = app / "android/gradle/verification-metadata.xml"
        verification.parent.mkdir(exist_ok=True)
        verification.write_bytes(verification_xml(pins))
        shutil.copy2(verification, provenance / verification.name)
        env.update(CARGO_TARGET_DIR=str(app / "target"), NVPN_FIPS_REPO_PATH=str(fips),
                   NVPN_EXPECTED_FIPS_GIT_SHA=pins["fips"]["commit"], NVPN_EXPECTED_FIPS_VERSION=pins["fips"]["version"],
                   NVPN_BUILD_GIT_SHA=pins["app"]["commit"], ANDROID_HOME=str(sdk), ANDROID_SDK_ROOT=str(sdk),
                   NVPN_ANDROID_FIPS_METADATA_RECEIPT=str(provenance / "fips-linkage.json"),
                   NVPN_ANDROID_FIPS_REBUILD_MARKER=str(provenance / "forced-rebuild.marker"),
                   NVPN_HOSTED_ENV_RECEIPT=str(provenance / "build-environment.json"),
                   SOURCE_DATE_EPOCH=capture("git", "-C", str(app), "show", "-s", "--format=%ct", "HEAD"))
        unsigned_environment(env)
        (provenance / "build.sh").write_text(BUILD_SCRIPT)
        session.run(["bash", str(provenance / "build.sh")], cwd=app, env=env)
        require((app / "Cargo.lock").read_bytes() == (provenance / "realized-Cargo.lock").read_bytes(), "Realized graph changed")
        product = export_bundle(app, fips, output, pins, session, env, tools)
        exact_source(fips, pins["fips"])
        require(set(capture("git", "-C", str(app), "diff", "--name-only").splitlines()) <= {"Cargo.lock"},
                "Frozen product source changed")
        scripts = ["tools/run-android", "scripts/release_common.sh", "scripts/local-fips-workspace.sh",
                   "scripts/prepare-android-release-from-bundle.sh", "scripts/verify-cargo-path-patch-lock.py"]
        receipt = {"schema": 1, "platform": "android", "configuration": "Release",
                   "distributionSigned": False, "runtimeTestsExecuted": False, "releaseAccepted": False,
                   "scope": "Unsigned hosted Android compilation; local signing and device acceptance required",
                   "source": identities, "producer": {"commit": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"],
                   "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "job": os.environ["GITHUB_JOB"],
                   "repository": os.environ["GITHUB_REPOSITORY"]}, "imageVersion": os.environ.get("ImageVersion"),
                   "toolVersions": {"rustc": capture(str(tools / "rust/bin/rustc"), "--version"),
                                    "cargo": capture(str(tools / "rust/bin/cargo"), "--version"),
                                    "java": capture(str(java / "bin/java"), "-version"),
                                    "clang": capture(str(tools / "android-ndk-r28c/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"), "--version"),
                                    "hostCc": capture("cc", "--version").splitlines()[0]},
                   "canonicalScripts": {path: digest(app / path) for path in scripts},
                   "rust": {"target": pins["target"], "package": "nostr-vpn-app-core", "profile": "release",
                            "defaultFeatures": True, "additionalFeatures": []},
                   "signingInputsAbsent": True, "signed": False, "buildExitCode": 0, **product}
        session.guard()
        session.save_resources()
        shutil.copy2(output / "build.log", provenance / "build.log")
        shutil.copy2(output / "resources.json", provenance / "resources.json")
        receipt["files"] = {str(path.relative_to(output)): file_record(path)
                            for path in sorted(output.rglob("*")) if path.is_file()}
        (provenance / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"compiled": True, "signed": False, "source": identities,
                          "unsignedAab": file_record(output / "unsigned/app-release.aab")}))
    finally:
        if committed_lock is not None:
            (app / "Cargo.lock").write_bytes(committed_lock)
        if not (provenance / "receipt.json").exists():
            session.save_resources()
            report = app / "android/build/reports/dependency-verification"
            if report.is_dir():
                shutil.copytree(report, output / "verification-failure")


def collect_receipts(output, pins, run_id, producer_commit):
    """Read an authenticated hosted artifact; never run or admit its products."""
    from android_hosted_content import zip_identity
    require(os.environ.get("GITHUB_ACTIONS") == "true", "Artifact receipt collection stays off the Mac")
    require(run_id > 0 and len(producer_commit) == 40 and
            all(c in "0123456789abcdef" for c in producer_commit), "Exact producer identity is required")
    require(not output.exists(), "Receipt collection output must be new")
    output.mkdir()
    session = BuildSession(output, pins)
    repository = "mmalmi/nostr-vpn"
    def api(path):
        return json.loads(capture("gh", "api", "repos/" + repository + path))
    run = api("/actions/runs/" + str(run_id))
    require(run["id"] == run_id and run["head_sha"] == producer_commit and
            run["path"] == ".github/workflows/android-release-inputs.yml" and
            run["repository"]["full_name"] == repository and run["event"] == "workflow_dispatch" and
            run["status"] == "completed" and run["conclusion"] == "success", "Producer run is not the exact successful run")
    jobs = [job for job in api("/actions/runs/" + str(run_id) + "/jobs?per_page=100")["jobs"] if job["name"] == "inputs"]
    require(len(jobs) == 1, "Producer platform job is ambiguous")
    job = jobs[0]
    require(job["head_sha"] == producer_commit and job["run_id"] == run_id and
            job["run_attempt"] == run["run_attempt"] and job["status"] == "completed" and
            job["conclusion"] == "success", "Producer platform job did not succeed on this attempt")
    artifacts = [item for item in api("/actions/runs/" + str(run_id) + "/artifacts")["artifacts"]
                 if item["name"] == "android-release-inputs-52a1f8ee" and not item["expired"]]
    require(len(artifacts) == 1, "Producer service artifact is ambiguous")
    artifact = artifacts[0]
    require(artifact["workflow_run"]["id"] == run_id and artifact["workflow_run"]["head_sha"] == producer_commit
            and artifact["created_at"] >= job["started_at"] and 0 < artifact["size_in_bytes"] <= 512 * 1024**2,
            "Service artifact identity, attempt or size differs")
    with tempfile.TemporaryDirectory(prefix="android-artifact-proof-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary)
        package = root / "github-artifact.zip"
        session.run(["gh", "api", "repos/" + repository + "/actions/artifacts/" + str(artifact["id"]) + "/zip"],
                    stdout_path=package)
        require(package.stat().st_size == artifact["size_in_bytes"] and "sha256:" + digest(package) == artifact["digest"],
                "Service ZIP bytes differ from GitHub's authenticated digest")
        identities = zip_identity(package)
        require(identities["provenance/receipt.json"]["bytes"] <= 2 * 1024**2, "Producer receipt exceeds its bound")
        with zipfile.ZipFile(package) as archive:
            receipt_bytes = archive.read("provenance/receipt.json")
            receipt = json.loads(receipt_bytes)
            require(receipt["source"] == {key: {name: pins[key][name] for name in ("commit", "tree")}
                                          for key in ("app", "fips")}, "Artifact source graph differs")
            require(receipt["producer"] == {"commit": producer_commit, "runId": str(run_id), "attempt": str(run["run_attempt"]),
                                          "job": "inputs", "repository": repository}, "Artifact producer identity differs")
            require(receipt["buildExitCode"] == 0 and receipt["signed"] is False and receipt["releaseAccepted"] is False,
                    "Artifact is not the expected unsigned producer output")
            require(set(identities) == set(receipt["files"]) | {"provenance/receipt.json"}, "ZIP export manifest differs")
            for name, expected in receipt["files"].items():
                require(identities[name] == {"sha256": expected["sha256"], "bytes": expected["size"]},
                        "Exported file does not match its recorded identity")
            aab = root / "app-release.aab"
            with archive.open("unsigned/app-release.aab") as source, aab.open("xb") as destination:
                shutil.copyfileobj(source, destination)
        bundle = zip_identity(aab)
        native = {name: identity for name, identity in bundle.items() if name.startswith("base/lib/") and name.endswith(".so")}
        require(set(native) == set(receipt["jniPayloads"]), "AAB native payload set differs")
        for name, identity in native.items():
            exported = identities["unsigned/jni/" + name.removeprefix("base/lib/")]
            require(identity == exported and identity == {"sha256": receipt["jniPayloads"][name]["sha256"],
                    "bytes": receipt["jniPayloads"][name]["size"]}, "AAB and exported JNI bytes differ")
        jni = native["base/lib/arm64-v8a/libnostr_vpn_app_core.so"]
        require(jni == {"sha256": receipt["compiledJni"]["sha256"], "bytes": receipt["compiledJni"]["size"]},
                "AAB does not contain the recorded compiled JNI")
        session.guard()
        (output / "producer-receipt.json").write_bytes(receipt_bytes)
        proof = {"schema": 1, "productExecuted": False, "nativeAdmissionPerformed": False,
                 "authentication": {"repository": repository, "workflow": run["path"], "producerCommit": producer_commit,
                 "runId": str(run_id), "runAttempt": str(run["run_attempt"]), "jobId": job["id"], "jobName": "inputs",
                 "jobConclusion": "success", "artifactId": artifact["id"], "artifactName": artifact["name"],
                 "artifactBytes": artifact["size_in_bytes"], "artifactSha256": digest(package)},
                 "producerReceiptSha256": identities["provenance/receipt.json"]["sha256"],
                 "aabSha256": identities["unsigned/app-release.aab"]["sha256"], "jniSha256": jni["sha256"],
                 "verifiedExportFiles": len(receipt["files"]), "collectorCommit": os.environ["GITHUB_SHA"],
                 "collectorRunId": os.environ["GITHUB_RUN_ID"], "validatorCommit": "3f6dbc53c40d319c01e25ed177769d398d81bd1f"}
        (output / "artifact-proof.json").write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
        session.save_resources()
        print(json.dumps(proof, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inventory", "qualify-ndk", "build", "collect-receipts"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--app", type=Path)
    parser.add_argument("--fips", type=Path)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--producer-commit")
    args = parser.parse_args()
    pins = json.loads(PINS.read_text())
    unsigned_environment(os.environ)
    if args.operation == "inventory":
        inventory(args.output, pins)
    elif args.operation == "qualify-ndk":
        qualify_ndk(args.output, pins)
    elif args.operation == "build":
        require(args.app and args.fips, "Frozen product and FIPS checkouts are required")
        build(args.output.resolve(), pins, args.app.resolve(), args.fips.resolve())
    else:
        require(args.run_id and args.producer_commit, "An exact successful producer run and commit are required")
        collect_receipts(args.output.resolve(), pins, args.run_id, args.producer_commit)


if __name__ == "__main__":
    main()
