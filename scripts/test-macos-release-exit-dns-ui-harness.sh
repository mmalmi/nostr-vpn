#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="$ROOT/scripts/macos-vm-release-exit-dns-ui-e2e.sh"
REMOTE="$ROOT/scripts/macos-release-exit-dns-ui-remote.sh"
DRIVER="$ROOT/scripts/macos-exit-dns-ax.swift"
RECEIPT="$ROOT/scripts/macos_exit_dns_ui_receipt.py"

bash -n "$HOST" "$REMOTE"
python3 -m py_compile "$RECEIPT"
xcrun swiftc -typecheck \
  -framework AppKit \
  -framework ApplicationServices \
  -framework Foundation \
  "$DRIVER"

python3 - "$HOST" "$REMOTE" "$DRIVER" "$RECEIPT" <<'PY'
import pathlib
import re
import sys

host, remote, driver, receipt = [
    pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[1:]
]
for required in (
    "macos_vm_prepare_or_verify_imported_release",
    'NVPN_MACOS_IMPORTED_RELEASE_ARTIFACT_READY:-0',
    '$ROOT/artifacts/mobile-release-join',
    "NVPN_EXPECTED_MACOS_IMPORT_VERIFICATION_SHA256",
    'shasum -a 256 "$IMPORT_VERIFICATION"',
    'receipt.get("appGitSha", "")',
    'proof.get("candidate_app_git_sha", "")',
    '--expected-app-head "$PRODUCT_APP_GIT_SHA"',
    '--expected-app-tree "$PRODUCT_APP_GIT_TREE"',
    "xcrun swiftc -O",
    "codesign --force --timestamp --options runtime",
    "create-driver",
    "create-summary",
):
    if required not in host:
        raise SystemExit(f"macOS DNS host orchestrator lacks {required}")
if 'IMPORT_RESULT="${NVPN_RELEASE_JOIN_RESULT_DIR:-$RESULT_DIR/import}"' in host:
    raise SystemExit(
        "macOS DNS host orchestrator still redirects prepared artifact reuse "
        "to its empty per-lane import directory"
    )
for prohibited in ("ssh macos-build", "ssh xcodebuild", "NVPN_APP_DATA_DIR="):
    if prohibited in host:
        raise SystemExit(f"macOS DNS host orchestrator contains {prohibited}")
if '--expected-app-head "$APP_GIT_SHA"' in host:
    raise SystemExit("macOS DNS driver validation confuses harness and product SHA")
for required in (
    '"$APP_EXE"',
    "lib-macos-owned-test-app.sh",
    "macos_open -n -F",
    'macos_open "$APP_PATH"',
    '--args --hidden',
    "/usr/bin/open",
    "macos_exact_executable_pids",
    "stop_gate_app",
    '"$DRIVER" "$APP_PID" --wait-window "Nostr VPN"',
    "Requesting the existing macOS app to reopen its main window",
    "stop_gate_app || return 1",
    'apply "$case"',
    'readback "$case"',
    "automatic cloudflare quad9 custom through-exit",
    "CANONICAL_DATA",
    "BACKUP_ROOT",
    "restore_profile",
    "quiesce_system_service",
    'sudo -n /bin/launchctl bootout "$SYSTEM_SERVICE_LABEL"',
    "restore_system_service",
    'sudo -n /bin/launchctl bootstrap system "$SYSTEM_SERVICE_PLIST"',
    'sudo -n /bin/launchctl kickstart -k "$SYSTEM_SERVICE_LABEL"',
    "validate-driver",
    "create-case",
    "EXPECTED_IMPORT_VERIFICATION_SHA256",
    'shasum -a 256 "$IMPORT_VERIFICATION"',
):
    if required not in remote:
        raise SystemExit(f"macOS DNS VM runner lacks {required}")
for prohibited in (
    "NVPN_APP_DATA_DIR=",
    "cat \"$CANONICAL_DATA",
    "grep \"$CANONICAL_DATA",
    'pkill -x "Nostr VPN"',
):
    if prohibited in remote:
        raise SystemExit(f"macOS DNS VM runner reads/injects private state: {prohibited}")
if re.search(r'(?m)^\s*"\$APP_EXE"(?:\s|$)', remote):
    raise SystemExit("macOS DNS VM runner executes the bundle binary directly")
if "macos-release-mobile-join-remote.sh\" verify-import" in remote:
    raise SystemExit("macOS DNS VM runner redundantly re-runs import verification")
for required in (
    "exit-dns-mode",
    "exit-dns-provider",
    "exit-dns-custom-url",
    "exit-dns-bootstrap-ips",
    "exit-dns-through-servers",
    "exit-dns-save",
    "https://dns.google/dns-query",
    "8.8.8.8,8.8.4.4",
    "10.99.79.53",
    "network-setup-create",
    "network-create-submit",
    "main-AppWindow-1",
    'args[2] == "--wait-window"',
    "MACOS_EXIT_DNS_AX_WINDOW_READY",
    "timeout: 60",
    "let finalElements = descendants(application)",
    "func blockingModalText(",
    "func pressSidebar(",
    "func pressAndWaitForSaveCompletion(",
    "try pressAndWaitForSaveCompletion(application)",
    "let inFlightProbeDeadline = Date().addingTimeInterval(5)",
    "if !observedInFlight {",
    "Exit DNS save was not actionable after the completion probe",
    "Exit DNS save did not complete",
    "Date().addingTimeInterval(75)",
    "let actionDeadline = Date().addingTimeInterval(20)",
    "findNow(window, identifier: identifier)",
    "kAXEnabledAttribute",
    "var lastActionError: AXError?",
    "if let lastActionError",
    "error != .failure",
    "error != .cannotComplete",
    "error != .invalidUIElement",
    '"AXScrollToVisible" as CFString',
    "kAXVerticalScrollBarAttribute",
    "NSNumber(value: fraction)",
):
    if required not in driver:
        raise SystemExit(f"macOS DNS AX driver lacks {required}")
if "Thread.sleep(forTimeInterval: 1)" in driver:
    raise SystemExit(
        "macOS DNS AX driver uses a fixed delay instead of observing save completion"
    )
if 'try press(application, "exit-dns-save")' in driver:
    raise SystemExit("macOS DNS AX driver bypasses the save-completion handshake")
if driver.count("try pressAndWaitForSaveCompletion(application)") != 1:
    raise SystemExit("macOS DNS AX driver does not use exactly one save handshake")
set_text_body = driver[
    driver.index("func setText(") : driver.index("func selectPicker(")
]
for required in (
    "kAXFocusedAttribute",
    "postKey(to: pid, keyCode: 0, flags: .maskCommand)",
    "keyboardSetUnicodeString",
):
    if required not in set_text_body:
        raise SystemExit(
            f"macOS DNS AX text entry lacks user-like input step: {required}"
        )
if "let directError" in set_text_body:
    raise SystemExit(
        "macOS DNS AX text entry bypasses SwiftUI bindings with a direct AX value write"
    )
press_body = driver[
    driver.index("func press(") : driver.index("func pressSidebar(")
]
if ".failure" in press_body or "actionDeadline" in press_body:
    raise SystemExit("macOS DNS AX driver retries non-idempotent generic presses")
sidebar_body = driver[
    driver.index("func pressSidebar(") : driver.index("func postKey(")
]
activation = sidebar_body.index(
    "NSRunningApplication(processIdentifier: pid)?.activate"
)
retry_loop = sidebar_body.index("repeat {")
if activation > retry_loop or sidebar_body.count(
    "NSRunningApplication(processIdentifier: pid)?.activate"
) != 1:
    raise SystemExit(
        "macOS DNS AX sidebar retry repeatedly activates the app instead of "
        "reacquiring controls within the exact window"
    )
if "kAXMainAttribute" in sidebar_body or "kAXFocusedAttribute" in sidebar_body:
    raise SystemExit(
        "macOS DNS AX sidebar retry passively blocks on fragile main/focused state"
    )
sidebar_calls = re.findall(
    r'try pressSidebar\(application, "([^"]+)", pid: pid\)',
    driver,
)
if sidebar_calls != [
    "sidebar-internet",
    "sidebar-devices",
    "sidebar-internet",
    "sidebar-internet",
]:
    raise SystemExit(
        "macOS DNS AX sidebar retry is not limited to the four idempotent "
        f"navigation actions: {sidebar_calls}"
    )
for required in (
    '"publicUiOnly": true',
    '"privateStateRead": false',
    '"savedViaShippedUi": saved',
    '"networkCreatedViaShippedUi": networkCreated',
):
    if required not in driver:
        raise SystemExit(f"macOS DNS AX evidence lacks {required}")
for required in (
    '"automatic"',
    '"cloudflare"',
    '"quad9"',
    '"custom"',
    '"through-exit"',
    '"uiRestartReadback": True',
    '"appArtifactReceiptSha256"',
    '"driverReceiptSha256"',
    '"canonicalProfileRestored": True',
    '"preexistingSystemServiceWasLoaded"',
    '"preexistingSystemServiceRestored"',
    '"harnessGitSha"',
    '"harnessGitTree"',
):
    if required not in receipt:
        raise SystemExit(f"macOS DNS receipt contract lacks {required}")
PY

tmp="$(mktemp -d "${TMPDIR:-/tmp}/nvpn-macos-dns-contract.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
python3 - "$RECEIPT" "$tmp" <<'PY'
import importlib.util
import json
import pathlib
import sys
from types import SimpleNamespace

helper = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2]) / "identity-contract"
root.mkdir(parents=True)
sys.path.insert(0, str(helper.parent))
spec = importlib.util.spec_from_file_location("macos_exit_dns_ui_receipt", helper)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

product_head = "50ee66ed6c112ebc2100aa9bd6afa21f2a21a0c0"
product_tree = "ff5866ae8421c56b343ac0e25a00dcb82f8547ef"
harness_head = "5fb33509d27358befc386b502c16f2727715d2e6"
harness_tree = "1" * 40
identity = "2" * 40
signer = "3" * 64
team = "TEAM123456"

app = root / "Nostr VPN.app"
executable = app / "Contents" / "MacOS" / "Nostr VPN"
executable.parent.mkdir(parents=True)
executable.write_bytes(b"exact product executable")
driver = root / "macos-exit-dns-ax"
driver.write_bytes(b"current harness driver")
driver_source = root / "macos-exit-dns-ax.swift"
driver_source.write_text("// current harness source\n", encoding="utf-8")
app_receipt = {
    "receiptSchema": 1,
    "artifactType": "macOS company Developer ID Release gate package",
    "companySigningVerified": True,
    "configuration": "Release",
    "builtOnHost": True,
    "builtOnTestVm": False,
    "appGitSha": product_head,
    "appGitTree": product_tree,
    "appSourceManifestSha256": "4" * 64,
    "appExecutableSha256": module.sha256_file(executable),
    "appBundleTreeSha256": module.tree_sha256(app),
    "fipsGitSha": "5" * 40,
    "fipsGitTree": "6" * 40,
    "fipsCoreVersion": "0.4.55",
    "signingTeam": team,
    "appCodeDirectoryHash": "7" * 40,
    "signingIdentitySha1": identity,
    "signerCertificateSha256": signer,
}
app_receipt_path = root / "artifact.json"
app_receipt_path.write_text(json.dumps(app_receipt), encoding="utf-8")

module.git_snapshot = lambda _root: {
    "head": harness_head,
    "tree": harness_tree,
    "manifest": "8" * 64,
}
module.tracked_source_sha = lambda _root, _source: "9" * 64
module.inspect_signature = lambda path, deep=False: {
    "team": team,
    "cdhash": "7" * 40 if pathlib.Path(path).suffix == ".app" else "a" * 40,
    "certificateSha1": identity,
    "certificateSha256": signer,
}
module.verify_signature = lambda *args, **kwargs: None

observed = module.observed_driver(
    SimpleNamespace(
        app_root=str(root),
        driver_source=str(driver_source),
        driver=str(driver),
        app=str(app),
        app_receipt=str(app_receipt_path),
        expected_app_head=product_head,
        expected_app_tree=product_tree,
        expected_team=team,
        expected_identity_sha1=identity,
        expected_signer_sha256=signer,
    )
)
if observed["appGitSha"] != product_head or observed["appGitTree"] != product_tree:
    raise SystemExit("driver receipt replaced the exact product identity")
if observed["appSourceManifestSha256"] != app_receipt["appSourceManifestSha256"]:
    raise SystemExit("driver receipt replaced the exact product source manifest")
if observed["harnessGitSha"] != harness_head or observed["harnessGitTree"] != harness_tree:
    raise SystemExit("driver receipt did not bind the current harness identity")
PY

python3 - "$RECEIPT" "$tmp" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

helper = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])


def write(name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


app = write(
    "app.json",
    {
        "appGitSha": "a" * 40,
        "appGitTree": "b" * 40,
        "fipsGitSha": "c" * 40,
        "fipsGitTree": "d" * 40,
        "fipsCoreVersion": "1.2.3",
        "appExecutableSha256": "e" * 64,
        "cliExecutableSha256": "0" * 64,
        "appBundleTreeSha256": "f" * 64,
    },
)
driver = write(
    "driver.json",
    {
        "appGitSha": "a" * 40,
        "appGitTree": "b" * 40,
        "fipsGitSha": "c" * 40,
        "fipsGitTree": "d" * 40,
        "fipsCoreVersion": "1.2.3",
        "appExecutableSha256": "e" * 64,
        "appBundleTreeSha256": "f" * 64,
        "appArtifactReceiptSha256": digest(app),
        "driverExecutableSha256": "1" * 64,
        "driverSourceSha256": "2" * 64,
    },
)
imported = write(
    "import.json",
    {
        "receiptSchema": 1,
        "remoteImportVerified": True,
        "artifactReceiptSha256": digest(app),
        "appGitSha": "a" * 40,
        "appGitTree": "b" * 40,
    },
)
verified = write(
    "driver-verification.json",
    {
        "receiptSchema": 1,
        "remoteDriverVerified": True,
        "driverReceiptSha256": digest(driver),
        "appArtifactReceiptSha256": digest(app),
        "appGitSha": "a" * 40,
        "appGitTree": "b" * 40,
    },
)
specs = {
    "automatic": ("automatic", "Automatic (recommended)", None, None, None, None),
    "cloudflare": ("encrypted", "Encrypted DNS", "cloudflare", "Cloudflare", None, None),
    "quad9": ("encrypted", "Encrypted DNS", "quad9", "Quad9", None, None),
    "custom": (
        "encrypted",
        "Encrypted DNS",
        "custom",
        "Custom DoH",
        "https://dns.google/dns-query",
        "8.8.8.8,8.8.4.4",
    ),
    "through-exit": ("through_exit", "DNS through exit", None, None, None, None),
}
case_dir = root / "cases"
for index, (case, spec) in enumerate(specs.items()):
    mode, mode_label, provider, provider_label, url, bootstrap = spec
    controls = ["exit-dns-mode", "exit-dns-save"]
    values = {"mode": mode, "modeLabel": mode_label, "rawModeValue": mode_label}
    if provider:
        controls.append("exit-dns-provider")
        values.update(
            {
                "provider": provider,
                "providerLabel": provider_label,
                "rawProviderValue": provider_label,
            }
        )
    if url:
        controls += ["exit-dns-custom-url", "exit-dns-bootstrap-ips"]
        values.update({"customUrl": url, "bootstrapIps": bootstrap})
    if case == "through-exit":
        controls.append("exit-dns-through-servers")
        values["throughServers"] = "10.99.79.53"
    observations = []
    for phase_number, phase in enumerate(("apply", "readback")):
        observations.append(
            write(
                f"obs/{case}-{phase}.json",
                {
                    "receiptSchema": 1,
                    "phase": phase,
                    "case": case,
                    "pid": 1000 + index * 2 + phase_number,
                    "processName": "Nostr VPN",
                    "publicUiOnly": True,
                    "privateStateRead": False,
                    "savedViaShippedUi": phase == "apply",
                    "networkCreatedViaShippedUi": (
                        case == "automatic" and phase == "apply"
                    ),
                    "visibleControlIdentifiers": sorted(controls),
                    "values": values,
                    "observedAtUnixMilliseconds": 10000 + index * 2 + phase_number,
                },
            )
        )
    output = case_dir / f"{case}.json"
    subprocess.run(
        [
            sys.executable,
            str(helper),
            "create-case",
            "--case",
            case,
            "--apply-observation",
            str(observations[0]),
            "--readback-observation",
            str(observations[1]),
            "--app-receipt",
            str(app),
            "--driver-receipt",
            str(driver),
            "--import-verification",
            str(imported),
            "--driver-verification",
            str(verified),
            "--output",
            str(output),
        ],
        check=True,
    )
restoration = write(
    "restoration.json",
    {
        "receiptSchema": 1,
        "canonicalProfileRestored": True,
        "preexistingAppStateRestored": True,
        "gateAppProcessesStopped": True,
        "preexistingSystemServiceWasLoaded": True,
        "preexistingSystemServiceWasRunning": True,
        "preexistingSystemServiceRestored": True,
        "preexistingSystemServiceRunningRestored": True,
    },
)
subprocess.run(
    [
        sys.executable,
        str(helper),
        "create-summary",
        "--case-dir",
        str(case_dir),
        "--app-receipt",
        str(app),
        "--driver-receipt",
        str(driver),
        "--import-verification",
        str(imported),
        "--driver-verification",
        str(verified),
        "--restoration-receipt",
        str(restoration),
        "--output",
        str(root / "summary.json"),
    ],
    check=True,
)
if not json.loads((root / "summary.json").read_text())[
    "allDnsOptionsSavedAndRelaunchRead"
]:
    raise SystemExit("macOS Exit DNS summary is not strict")

tampered = json.loads((root / "obs/custom-readback.json").read_text())
tampered["values"]["bootstrapIps"] = "1.1.1.1"
write("obs/custom-readback-tampered.json", tampered)
rejected = subprocess.run(
    [
        sys.executable,
        str(helper),
        "create-case",
        "--case",
        "custom",
        "--apply-observation",
        str(root / "obs/custom-apply.json"),
        "--readback-observation",
        str(root / "obs/custom-readback-tampered.json"),
        "--app-receipt",
        str(app),
        "--driver-receipt",
        str(driver),
        "--import-verification",
        str(imported),
        "--driver-verification",
        str(verified),
        "--output",
        str(root / "tampered.json"),
    ],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
if rejected.returncode == 0:
    raise SystemExit("tampered macOS DNS readback was accepted")
PY

echo "MACOS_RELEASE_EXIT_DNS_UI_HARNESS_OK"
