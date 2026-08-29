#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANUAL_JOIN_DRIVER="$ROOT/scripts/desktop-manual-join-ax.swift"
SERVICE_TOGGLE_DRIVER="$ROOT/scripts/macos-service-toggle-ax.swift"

files=(
  "$ROOT/scripts/macos-vm-release-mobile-join-e2e.sh"
  "$ROOT/scripts/macos-release-mobile-join-remote.sh"
  "$ROOT/scripts/macos-vm-manual-join-e2e.sh"
  "$ROOT/scripts/macos-vm-service-toggle-e2e.sh"
  "$ROOT/scripts/macos-vm-release-exit-dns-ui-e2e.sh"
  "$ROOT/scripts/macos-vm-desktop-app-launch-smoke.sh"
  "$ROOT/scripts/macos-vm-desktop-wireguard-exit-e2e.sh"
  "$ROOT/scripts/macos-vm-desktop-daemon-idle-e2e.sh"
  "$ROOT/scripts/e2e-macos-release-network.sh"
  "$ROOT/scripts/e2e-macos-manual-join-ui.sh"
  "$ROOT/scripts/e2e-macos-service-toggle.sh"
  "$ROOT/scripts/macos-app-launch-smoke.sh"
  "$ROOT/scripts/e2e-wireguard-exit-host.sh"
  "$ROOT/scripts/e2e-macos-service.sh"
  "$ROOT/scripts/lib-macos-owned-test-app.sh"
  "$ROOT/scripts/release-gate.sh"
)
for file in "${files[@]}"; do
  bash -n "$file"
done
python3 -B "$ROOT/scripts/macos_release_join_artifact.py" --help >/dev/null
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-vm-imported-release.sh"
[[ "$(macos_vm_imported_release_package "src/nostr-vpn")" \
  == "artifacts/macos-release-mobile-join/imported" ]]
[[ "$(macos_vm_imported_release_package "/tmp/src/nostr-vpn")" \
  == "/tmp/src/nostr-vpn/artifacts/macos-release-mobile-join/imported" ]]

# shellcheck disable=SC1091
source "$ROOT/scripts/lib-macos-owned-test-app.sh"
ps() {
  cat <<'EOF'
 101 /Applications/Nostr VPN.app/Contents/MacOS/Nostr VPN
 202 /tmp/imported/Nostr VPN.app/Contents/MacOS/Nostr VPN
 303 /tmp/imported/Nostr VPN.app/Contents/MacOS/Nostr VPN Helper
EOF
}
[[ "$(macos_exact_executable_pids \
  "/tmp/imported/Nostr VPN.app/Contents/MacOS/Nostr VPN")" == "202" ]]
unset -f ps

python3 - "${files[@]}" "$ROOT/scripts/macos_release_join_artifact.py" \
  "$ROOT/scripts/macos-build" "$MANUAL_JOIN_DRIVER" "$SERVICE_TOGGLE_DRIVER" <<'PY'
import pathlib
import sys

paths = [pathlib.Path(value) for value in sys.argv[1:]]
texts = {path.name: path.read_text(encoding="utf-8") for path in paths}

host = texts["macos-vm-release-mobile-join-e2e.sh"]
remote = texts["macos-release-mobile-join-remote.sh"]
artifact = texts["macos_release_join_artifact.py"]
macos_build = texts["macos-build"]
release_gate = texts["release-gate.sh"]
exit_dns = texts["macos-vm-release-exit-dns-ui-e2e.sh"]

if 'TEST_CONFIG_DIR="/tmp/nvpn-rj-$UID"' not in remote:
    raise SystemExit("macOS join profile lacks a stable short config directory")
if 'TEST_CONFIG_DIR="$PROFILE_STATE_DIR/test"' in remote:
    raise SystemExit("macOS join profile still places its Unix socket under caches")
if 'CONFIG="$TEST_CONFIG_DIR/config.toml"' not in remote:
    raise SystemExit("macOS join CLI does not use the daemon's canonical config path")
if 'CONFIG="$CONFIG_DIR/config.toml"' in remote:
    raise SystemExit("macOS join CLI still uses the symlink config path")
if 'NVPN_APP_DATA_DIR="$TEST_CONFIG_DIR"' not in remote:
    raise SystemExit("macOS join GUI does not use the daemon's canonical profile")
if "outbound_join_request" in remote:
    raise SystemExit("macOS manual join harness still requires obsolete QR request state")
manual_join_phase = texts["desktop-manual-join-ax.swift"].split(
    'case "release-manual-join":', 1
)[1].split('case "release-joiner-id":', 1)[0]
if 'roster-participant-pending-\\(args[3])' not in manual_join_phase:
    raise SystemExit("macOS manual join UI does not prove pending roster state")
if 'roster-participant-accepted-\\(args[3])' in manual_join_phase:
    raise SystemExit("macOS manual join UI expects approval before the admin acts")
longest_short_socket = (
    "/private/tmp/nvpn-rj-4294967295/"
    ".nvpn-runtime/join-0123456789abcdef.sock"
)
if len(longest_short_socket.encode()) > 103:
    raise SystemExit("macOS join profile can exceed the Unix socket path limit")

for start, end in (
    ("# macOS admin -> physical Android joiner.", "# Physical Android admin -> macOS joiner."),
    ("# macOS admin -> physical iPhone joiner.", "# Physical iPhone admin -> macOS joiner."),
):
    direction = host.split(start, 1)[1].split(end, 1)[0]
    if 'kill "$remote_pid"' in direction or 'wait "$remote_pid"' not in direction:
        raise SystemExit("macOS admin hold is not cleanly joined before the next app launch")

listener = remote.split("assert_join_listener_ready() {", 1)[1].split(
    "\n}\n\nassert_outbound_join_ready", 1
)[0]
if 's.get("vpn_status") == "Waiting for participants"' not in listener:
    raise SystemExit("macOS join listener rejects the canonical empty-roster state")
if 's.get("vpn_status") == "Listening for join requests"' in listener:
    raise SystemExit("macOS join listener still expects an unreachable status")
if 'join_request_qr_code_or_link' in listener:
    raise SystemExit("macOS manual join listener still requires unrelated QR state")

cleanup = remote.split("restore_test_profile() {", 1)[1].split(
    "\n}\n\nservice_preflight", 1
)[0]
for required in (
    'service_pid="$(python3 -c',
    'service status --json --skip-binary-version --config "$CONFIG"',
    'ps -p "$service_pid" -o pid=',
):
    if required not in cleanup:
        raise SystemExit(f"macOS join cleanup lacks stopped-service proof: {required}")
if not (
    cleanup.index("service status --json")
    < cleanup.index("service uninstall")
    < cleanup.index('ps -p "$service_pid"')
    < cleanup.index("restore_config_dir")
):
    raise SystemExit("macOS join cleanup restores the profile before service stop proof")

for required in (
    'git -C "$ROOT" archive --format=tar "$APP_GIT_SHA"',
    'git clone --quiet --no-checkout --no-hardlinks',
    'checkout --quiet --detach "$RELEASE_JOIN_FIPS_SHA"',
    'MACOS_RUST_PROFILE="${NVPN_MACOS_RUST_PROFILE:-release}"',
    'MACOS_XCODE_CONFIGURATION="${NVPN_MACOS_XCODE_CONFIGURATION:-Release}"',
    '"$MACOS_RUST_PROFILE" != "release"',
    '"$MACOS_XCODE_CONFIGURATION" != "Release"',
    'NVPN_FIPS_REPO_PATH="$HOST_FIPS_ROOT"',
    'NVPN_MACOS_RUST_PROFILE="$MACOS_RUST_PROFILE"',
    'NVPN_MACOS_XCODE_CONFIGURATION="$MACOS_XCODE_CONFIGURATION"',
    '--fips-root "$HOST_FIPS_ROOT"',
    '"$HOST_BUILD_ROOT/scripts/macos-build" macos-app',
    '"$HOST_BUILD_ROOT/scripts/macos-build" macos-gate-support',
    'validate-published-app',
    '--require-gate-bundle-tree',
    'proveUnchangedPlatformInputs',
    'component-proof.json',
    '"$CACHE_FIPS_SHA" == "$RELEASE_JOIN_FIPS_SHA"',
    '"$CACHE_FIPS_TREE" == "$RELEASE_JOIN_FIPS_TREE"',
    '"$CACHE_FIPS_VERSION" == "$RELEASE_JOIN_FIPS_VERSION"',
    'PRODUCT_GIT_SHA',
    '--expected-harness-head "$APP_GIT_SHA"',
    "desktop_manual_join_e2e_fixture",
    "desktop-manual-join-ax",
    "macos-service-toggle-ax",
    "codesign --force",
    "ditto -c -k --sequesterRsrc --keepParent",
    "macos_release_join_artifact.py\" create",
):
    if required not in host:
        raise SystemExit(f"host macOS gate package is missing {required}")

for required in (
    "macos-gate-support",
    "swiftc",
    "desktop_manual_join_e2e_fixture",
):
    if required not in macos_build:
        raise SystemExit(f"host macOS support build is missing {required}")

for required in (
    "packageTreeSha256",
    "appExecutableSha256",
    "cliExecutableSha256",
    "manualJoinFixtureSha256",
    "manualJoinDriverSha256",
    "serviceToggleDriverSha256",
    "manualJoinFixtureCodeDirectoryHash",
    "manualJoinDriverCodeDirectoryHash",
    "serviceToggleDriverCodeDirectoryHash",
    "componentInputProof",
    "componentInputProofSha256",
    "tree_sha256(package)",
):
    if required not in artifact:
        raise SystemExit(f"macOS gate receipt omits {required}")

for forbidden in (
    "cargo build",
    "xcodebuild",
    "macos-build",
    "codesign --force",
    "/usr/bin/swift",
    "swift -e",
    "swiftc",
):
    if forbidden in remote:
        raise SystemExit(f"macOS artifact importer can execute VM-side {forbidden}")
for required in (
    "ditto -x -k",
    "macos_release_join_artifact.py\" validate",
    "verify-import",
    "verification.json",
):
    if required not in remote:
        raise SystemExit(f"macOS artifact importer is missing {required}")

wrapper_contracts = {
    "macos-vm-manual-join-e2e.sh": (
        "NVPN_MACOS_VM_IMPORT_ONLY=1",
        "NVPN_MACOS_APP_PATH=",
        "NVPN_DESKTOP_MANUAL_JOIN_FIXTURE=",
        "NVPN_DESKTOP_MANUAL_JOIN_DRIVER=",
    ),
    "macos-vm-service-toggle-e2e.sh": (
        "NVPN_MACOS_VM_IMPORT_ONLY=1",
        "NVPN_MACOS_APP_PATH=",
        "NVPN_DESKTOP_SERVICE_TOGGLE_FIXTURE=",
        "NVPN_DESKTOP_SERVICE_TOGGLE_DRIVER=",
    ),
    "macos-vm-desktop-app-launch-smoke.sh": (
        "NVPN_MACOS_VM_IMPORT_ONLY=1",
        "NVPN_MACOS_APP_PATH=",
        "NVPN_MACOS_APP_SMOKE_BUILD=0",
        "NVPN_MACOS_APP_IDLE_CPU_SAMPLE_SECONDS=",
        "NVPN_MACOS_APP_IDLE_CPU_SETTLE_SECONDS=",
    ),
    "macos-vm-desktop-wireguard-exit-e2e.sh": (
        "NVPN_MACOS_VM_IMPORT_ONLY=1",
        "NVPN_E2E_BINARY=",
        "e2e-macos-release-network.sh",
    ),
    "macos-vm-desktop-daemon-idle-e2e.sh": (
        "NVPN_MACOS_VM_IMPORT_ONLY=1",
        "NVPN_E2E_BINARY=",
        'REMOTE_RESULT="artifacts/macos-daemon-idle-cpu.json"',
        'REMOTE_RESULT_SCP="$GUEST_REPO/$REMOTE_RESULT"',
        'scp -q "$SSH_HOST:$REMOTE_RESULT_SCP"',
    ),
}
for name, required_values in wrapper_contracts.items():
    text = texts[name]
    if "macos_vm_prepare_or_verify_imported_release" not in text:
        raise SystemExit(f"{name} does not prepare/verify the host artifact")
    for required in required_values:
        if required not in text:
            raise SystemExit(f"{name} does not pass {required}")

import_only_children = {
    "e2e-macos-manual-join-ui.sh": (
        "NVPN_DESKTOP_MANUAL_JOIN_FIXTURE",
        "NVPN_DESKTOP_MANUAL_JOIN_DRIVER",
    ),
    "e2e-macos-service-toggle.sh": (
        "NVPN_DESKTOP_SERVICE_TOGGLE_FIXTURE",
        "NVPN_DESKTOP_SERVICE_TOGGLE_DRIVER",
    ),
    "macos-app-launch-smoke.sh": ("NVPN_MACOS_APP_SMOKE_BUILD=0",),
    "e2e-wireguard-exit-host.sh": ("NVPN_WG_EXIT_HOST_BINARY",),
    "e2e-macos-release-network.sh": ("NVPN_E2E_BINARY",),
    "e2e-macos-service.sh": ("NVPN_E2E_BINARY",),
}
for name, required_values in import_only_children.items():
    text = texts[name]
    if "NVPN_MACOS_VM_IMPORT_ONLY" not in text:
        raise SystemExit(f"{name} has no fail-closed VM import-only mode")
    for required in required_values:
        if required not in text:
            raise SystemExit(f"{name} import-only mode does not require {required}")
    for forbidden in ("/usr/bin/swift", "swift -e", "swiftc"):
        if forbidden in text:
            raise SystemExit(f"{name} can compile Swift on the VM through {forbidden}")

for name in (
    "e2e-macos-manual-join-ui.sh",
    "e2e-macos-service-toggle.sh",
):
    if "--check-accessibility" not in texts[name]:
        raise SystemExit(f"{name} does not use its imported AX driver for preflight")
    for required in (
        'APP_PATH="$(cd "$(dirname "$APP_PATH")" && pwd -P)/$(basename "$APP_PATH")"',
        "macos_exact_executable_pids",
        "macos_stop_exact_test_app",
        "trap 'exit 129' HUP",
        "trap 'exit 130' INT",
        "trap 'exit 143' TERM",
    ):
        if required not in texts[name]:
            raise SystemExit(f"{name} lacks exact imported-app cleanup: {required}")

for name in (
    "e2e-macos-manual-join-ui.sh",
    "e2e-macos-service-toggle.sh",
):
    if "trap cleanup EXIT" not in texts[name]:
        raise SystemExit(f"{name} does not restore acquired app ownership")
    for required in (
        "lib-macos-release-app-ownership.sh",
        "macos_release_app_acquire",
        "macos_release_app_restore",
    ):
        if required not in texts[name]:
            raise SystemExit(f"{name} lacks shared app ownership: {required}")

manual_join = texts["e2e-macos-manual-join-ui.sh"]
manual_join_driver = texts["desktop-manual-join-ax.swift"]
launch = manual_join.split("launch_app() {", 1)[1].split(
    "\n}\n\nlaunch_app", 1
)[0]
for required in (
    "open -n -F",
    '--env "NVPN_APP_DATA_DIR=$data_dir"',
    '--env "NVPN_CLI_PATH=$NVPN"',
    "macos_exact_executable_pids",
):
    if required not in launch:
        raise SystemExit(
            f"manual-join VM launch bypasses LaunchServices or exact PID ownership: {required}"
        )
if launch.index("open -n -F") > launch.index("macos_exact_executable_pids"):
    raise SystemExit("manual-join VM looks for its exact PID before launching")
if "Date().addingTimeInterval(20)" not in manual_join_driver:
    raise SystemExit("manual-join AX driver lacks a bounded cold-import readiness window")
press_driver = manual_join_driver.split("func press(", 1)[1].split(
    "\n}\n\nfunc setValue", 1
)[0]
for required in (
    "let candidates = visible.filter",
    "for candidate in candidates",
):
    if required not in press_driver:
        raise SystemExit(
            f"manual-join AX driver does not try every responsive-layout match: {required}"
        )
if "visible.first(where:" in press_driver:
    raise SystemExit(
        "manual-join AX driver can wedge on the first stale responsive-layout match"
    )

if 'pgrep -f "$APP_EXE"' in texts["e2e-macos-service-toggle.sh"]:
    raise SystemExit("service-toggle gate still uses substring process matching")

if "codesign --force" in texts["e2e-macos-service-toggle.sh"]:
    raise SystemExit("service-toggle gate still re-signs a VM-side app copy")

service_toggle = texts["e2e-macos-service-toggle.sh"]
for required in (
    'mktemp -d /tmp/nvpn-sg.XXXXXX',
    'chmod 700 "$DATA_ROOT"',
    'rm -rf -- "$DATA_ROOT"',
):
    if required not in service_toggle:
        raise SystemExit(f"service-toggle gate lacks short owned runtime cleanup: {required}")
if 'DATA_ROOT="$ARTIFACT_DIR/app-data"' in service_toggle:
    raise SystemExit("service-toggle gate still puts Unix sockets under artifacts")

service_toggle_driver = texts["macos-service-toggle-ax.swift"]
for required in (
    "NSRunningApplication(processIdentifier: pid)?.activate(",
    "options: [.activateAllWindows]",
    'findVisibleIdentifier(application, "main-AppWindow-1", timeout: 60)',
):
    if required not in service_toggle_driver:
        raise SystemExit(
            f"service-toggle AX driver does not reactivate and await the app window: {required}"
        )

service_toggle_launch = service_toggle.split("launch_app() {", 1)[1].split(
    "\n}\n\nif ! launch_app", 1
)[0]
for required in (
    "for launch_attempt in 1 2 3",
    'macos_stop_exact_test_app "$APP_EXE"',
    "open -n -F",
    "macos_exact_executable_pids",
):
    if required not in service_toggle_launch:
        raise SystemExit(
            f"service-toggle launch lacks bounded exact-app retry: {required}"
        )
if service_toggle_launch.index('macos_stop_exact_test_app "$APP_EXE"') > (
    service_toggle_launch.index("open -n -F")
):
    raise SystemExit("service-toggle retry launches before clearing its exact stale app")
if 'mktemp -d /tmp/nvpn-svc-e2e.XXXXXX' not in texts["e2e-macos-service.sh"]:
    raise SystemExit("service singleton gate lacks a short macOS runtime root")

for required in (
    "env NVPN_MACOS_RUST_PROFILE=release NVPN_MACOS_XCODE_CONFIGURATION=Release",
    "NVPN_MACOS_RELEASE_ARTIFACT_ACTION=prepare-only",
    "NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY=1",
    "NVPN_RELEASE_GATE_MACOS_WG_EXIT_E2E",
    "NVPN_RELEASE_GATE_MACOS_GUI_SMOKE",
    "NVPN_RELEASE_GATE_MACOS_DAEMON_IDLE_CPU",
):
    if required not in release_gate:
        raise SystemExit(f"release gate does not wire imported macOS artifacts: {required}")

for required in (
    '"${NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY:-0}"',
    'DEFAULT_IMPORT_RESULT="$ROOT/artifacts/mobile-release-join"',
    'IMPORT_RESULT="${NVPN_RELEASE_JOIN_RESULT_DIR:-$DEFAULT_IMPORT_RESULT}"',
):
    if required not in exit_dns:
        raise SystemExit(
            f"macOS Exit DNS UI gate cannot reuse the prepared exact app: {required}"
        )
if 'IMPORT_RESULT="${NVPN_RELEASE_JOIN_RESULT_DIR:-$RESULT_DIR/import}"' in exit_dns:
    raise SystemExit("macOS Exit DNS UI gate redirects reuse to an empty lane cache")
if "NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY=0" in exit_dns:
    raise SystemExit("macOS Exit DNS UI gate forces a duplicate signed app build")

for wrapper in wrapper_contracts:
    text = texts[wrapper]
    remote_index = text.find("remote_command=")
    if remote_index < 0:
        raise SystemExit(f"{wrapper} has no explicit remote command")
    remote_path = text[remote_index:]
    for forbidden in (
        "cargo build",
        "xcodebuild",
        "macos-build",
        "codesign --force",
        "/usr/bin/swift",
        "swift -e",
        "swiftc",
    ):
        if forbidden in remote_path:
            raise SystemExit(f"{wrapper} remote path contains {forbidden}")
PY

python3 - "$ROOT" <<'PY'
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
spec = importlib.util.spec_from_file_location(
    "macos_release_join_artifact",
    root / "scripts" / "macos_release_join_artifact.py",
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(prefix="nvpn-macos-git-snapshot.") as tmp:
    checkout = pathlib.Path(tmp)
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.name", "Release Harness"],
        check=True,
    )
    manifest = checkout / "Cargo.toml"
    lock = checkout / "Cargo.lock"
    tracked = checkout / "tracked.txt"
    manifest.write_text("[workspace]\n", encoding="utf-8")
    lock.write_text("committed\n", encoding="utf-8")
    tracked.write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "commit", "-qm", "fixture"], check=True
    )
    first_head = subprocess.check_output(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    current_snapshot = module.git_snapshot(checkout)
    tracked.write_text("next commit\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(checkout), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "commit", "-qm", "second fixture"], check=True
    )
    historical_snapshot = module.git_snapshot_at(checkout, first_head)
    assert historical_snapshot["manifest"] == current_snapshot["manifest"]
    lock.write_text("realized local FIPS lock\n", encoding="utf-8")
    os.environ["NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256"] = hashlib.sha256(
        manifest.read_bytes()
    ).hexdigest()
    os.environ["NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256"] = hashlib.sha256(
        lock.read_bytes()
    ).hexdigest()
    module.git_snapshot(checkout)
    tracked.write_text("dirty\n", encoding="utf-8")
    try:
        module.git_snapshot(checkout)
    except ValueError:
        pass
    else:
        raise SystemExit("git snapshot accepted unrelated release checkout changes")
    finally:
        os.environ.pop("NVPN_LOCAL_FIPS_SESSION_CARGO_TOML_SHA256", None)
        os.environ.pop("NVPN_LOCAL_FIPS_SESSION_CARGO_LOCK_SHA256", None)

signature = {
    "authority": "Developer ID Application: Test (ABCDEFGHIJ)",
    "cdhash": "1" * 40,
    "certificateSha1": "2" * 40,
    "certificateSha256": "3" * 64,
    "team": "ABCDEFGHIJ",
}
module.inspect_signature = lambda path, deep=False: dict(signature)
module.git_snapshot = lambda path: {
    "head": "4" * 40,
    "tree": "5" * 40,
    "manifest": "6" * 64,
}
module.git_snapshot_at = lambda path, head: {
    "head": "4" * 40,
    "tree": "5" * 40,
    "manifest": "6" * 64,
}
module.fips_version = lambda path: "0.4.45"

with tempfile.TemporaryDirectory(prefix="nvpn-macos-import-harness.") as tmp:
    work = pathlib.Path(tmp)
    package = work / "package"
    app = package / "Nostr VPN.app"
    executable = app / "Contents" / "MacOS" / "Nostr VPN"
    cli = app / "Contents" / "Resources" / "nvpn"
    fixture = package / "fixtures" / "desktop_manual_join_e2e_fixture"
    manual = package / "drivers" / "desktop-manual-join-ax"
    service = package / "drivers" / "macos-service-toggle-ax"
    component_proof = package / "component-proof.json"
    for path, payload in (
        (executable, b"app"),
        (cli, b"cli"),
        (fixture, b"fixture"),
        (manual, b"manual"),
        (service, b"service"),
        (component_proof, json.dumps({
            "policy": "unchanged-platform-product-inputs-v1",
            "platform": "macos",
            "receipt_app_git_sha": "4" * 40,
            "receipt_app_git_tree": "5" * 40,
            "candidate_app_git_sha": "7" * 40,
            "candidate_app_git_tree": "8" * 40,
            "changed_paths_sha256": "a" * 64,
        }).encode()),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o755)
    archive = work / "package.zip"
    archive.write_bytes(b"archive")
    receipt = work / "receipt.json"
    verification = work / "verification.json"
    args = argparse.Namespace(
        receipt=str(receipt),
        package=str(package),
        app=str(app),
        archive=str(archive),
        manual_join_fixture=str(fixture),
        manual_join_driver=str(manual),
        service_toggle_driver=str(service),
        component_proof=str(component_proof),
        app_root=str(work / "app-source"),
        fips_root=str(work / "fips-source"),
        expected_app_head="4" * 40,
        expected_app_tree="5" * 40,
        expected_harness_head="7" * 40,
        expected_harness_tree="8" * 40,
        expected_fips_head="4" * 40,
        expected_fips_tree="5" * 40,
        expected_fips_version="0.4.45",
        expected_team="ABCDEFGHIJ",
        expected_identity_sha1="2" * 40,
        expected_signer_sha256="3" * 64,
        verification_output=str(verification),
    )
    module.create_receipt(args)
    module.validate_receipt(args)
    value = module.load_json(receipt)
    assert value["appGitSha"] == "4" * 40
    assert value["componentInputProof"]["candidate_app_git_sha"] == "7" * 40
    for path in (executable, cli, fixture, manual, service, component_proof):
        original = path.read_bytes()
        path.write_bytes(original + b"-tampered")
        try:
            module.validate_receipt(args)
        except ValueError:
            pass
        else:
            raise SystemExit(f"receipt accepted tampered imported artifact: {path.name}")
        path.write_bytes(original)
        path.chmod(0o755)
    fixture.chmod(0o700)
    try:
        module.validate_receipt(args)
    except ValueError:
        pass
    else:
        raise SystemExit("receipt accepted a changed imported fixture mode")
PY

"$ROOT/scripts/test-macos-release-app-ownership-harness.sh"

echo "macOS VM host-build/import-only contract passed"
