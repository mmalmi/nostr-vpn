#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

required_source=(
  'macos/Sources/RootViewInternet.swift:.accessibilityIdentifier("exit-dns-mode")'
  'macos/Sources/RootViewInternet.swift:.accessibilityIdentifier("exit-dns-save")'
  'linux/src/main/saved_networks.rs:nvpn-exit-dns-mode'
  'linux/src/main/saved_networks.rs:nvpn-exit-dns-save'
  'windows/NostrVpn.Windows/MainWindow.xaml:AutomationProperties.AutomationId="ExitDnsMode"'
  'windows/NostrVpn.Windows/MainWindow.xaml:AutomationProperties.AutomationId="ExitDnsSave"'
  'scripts/desktop-mobile-manual-join-atspi.py:uiRestartReadback'
  'scripts/desktop-mobile-manual-join-atspi.py:invoke_until_visible("Internet", "nvpn-exit-dns-mode")'
  'scripts/desktop-mobile-manual-join-windows-ui.ps1:uiRestartReadback'
  'scripts/ubuntu-vm-exit-dns-ui-e2e.sh:DnsPolicy'
  'scripts/ubuntu-vm-exit-dns-ui-e2e.sh:source "$repo/scripts/lib-linux-owned-test-app.sh"'
  'scripts/ubuntu-vm-exit-dns-ui-e2e.sh:"$repo/scripts/test-linux-owned-test-app-harness.sh"'
  'scripts/ubuntu-vm-exit-dns-ui-e2e.sh:xvfb-run -a dbus-run-session -- env'
  'scripts/ubuntu-vm-exit-dns-ui-e2e.sh:artifact_root="$(cd "$artifact_root" && pwd -P)"'
  'scripts/ubuntu-vm-exit-dns-ui-e2e.sh:repo="$(pwd -P)"'
  'scripts/windows-vm-exit-dns-ui-e2e.sh:DnsPolicy'
)
for entry in "${required_source[@]}"; do
  file="${entry%%:*}"
  text="${entry#*:}"
  grep -Fq -- "$text" "$file" || {
    echo "desktop DNS UI source contract is missing: $file: $text" >&2
    exit 1
  }
done

python3 - "$ROOT/scripts/windows-vm-exit-dns-ui-e2e.sh" <<'PY'
import pathlib
import sys

script = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
for forbidden in ("& \\$cli init", "& \\$cli set"):
    if forbidden in script:
        raise SystemExit(
            "Windows Exit DNS UI gate bootstraps a legacy/default network "
            f"instead of letting the shipped app create an empty profile: {forbidden}"
        )
for required in (
    "isolated Windows DNS UI data directory already exists",
    "New-Item -ItemType Directory -Path \\$data",
    "if (!\\$?)",
):
    if required not in script:
        raise SystemExit(
            f"Windows Exit DNS UI gate lacks fresh-profile/PowerShell success handling: {required}"
        )
PY

python3 - \
  "$ROOT/scripts/ubuntu-vm-exit-dns-ui-e2e.sh" \
  "$ROOT/scripts/lib-linux-owned-test-app.sh" <<'PY'
import pathlib
import sys

script = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
helper = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
canonical_handoff = (
    'artifact_root="$(cd "$artifact_root" && pwd -P)"\n'
    'cd "$repo"\n'
    'repo="$(pwd -P)"\n'
    'export GDK_BACKEND=x11'
)
if canonical_handoff not in script:
    raise SystemExit(
        "Linux Exit DNS UI wrapper does not canonicalize its relative guest "
        "repository and artifact directory before handing them to the nested "
        "Xvfb/DBus shell"
    )
for required in (
    "cleanup_remote_dns_state()",
    'case_root="/tmp/nvpn-linux-exit-dns-ui"',
    'artifact_root="$guest_repo/artifacts/linux-exit-dns-ui"',
    '[[ "$artifact_root" == */nostr-vpn-release-gate/artifacts/linux-exit-dns-ui ]]',
    'test ! -e "$artifact_root"',
    'test ! -e "$case_root"',
    'linux_stop_exact_test_app "$app"',
    "xvfb-run -a dbus-run-session -- env",
):
    if required not in script:
        raise SystemExit(
            "Linux Exit DNS UI wrapper does not clean exact remote state "
            f"after cancellation: {required}"
        )
run_case_start = script.index("run_case() {")
run_case_end = script.index(
    'artifact_root="$(cd "$artifact_root" && pwd -P)"',
    run_case_start,
)
run_case = script[run_case_start:run_case_end]
if run_case.count("xvfb-run -a dbus-run-session -- env") != 1:
    raise SystemExit(
        "Linux Exit DNS UI wrapper does not isolate every DNS case in a "
        "fresh Xvfb/DBus accessibility session"
    )
matrix = script[run_case_end:]
if "xvfb-run -a dbus-run-session -- bash -s" in matrix:
    raise SystemExit(
        "Linux Exit DNS UI matrix still reuses one accessibility session"
    )
for required in (
    "linux_exact_executable_records()",
    "linux_exact_executable_pids()",
    "linux_signal_exact_executable()",
    "linux_stop_exact_test_app()",
    'for proc in /proc/[0-9]*',
    'readlink -f -- "$proc/exe"',
    'start_time="${20:-}"',
    'current_start="${20:-}"',
):
    if required not in helper:
        raise SystemExit(
            f"Linux exact-app cleanup helper lacks {required}"
        )
if 'pkill -f' in script or 'pkill -f' in helper:
    raise SystemExit(
        "Linux Exit DNS UI wrapper can kill its own SSH shell by matching "
        "the imported app path in argv"
    )
cleanup = script[
    script.index("cleanup() {") : script.index("trap cleanup EXIT")
]
dns_cleanup = cleanup.find("cleanup_remote_dns_state")
bundle_cleanup = cleanup.find("ubuntu_vm_cleanup_imported_release_bundle")
if dns_cleanup < 0 or bundle_cleanup < 0 or dns_cleanup > bundle_cleanup:
    raise SystemExit(
        "Linux Exit DNS UI wrapper does not remove exact DNS state before "
        "the slower imported-package cleanup"
    )
guest_cleanup_start = script.index(
    "cleanup() {",
    script.index('mkdir -p "$case_root" "$artifact_root"'),
)
guest_cleanup = script[
    guest_cleanup_start : script.index("trap cleanup EXIT", guest_cleanup_start)
]
for required in (
    'local status="$?"',
    'if ! linux_stop_exact_test_app "$app"; then',
    "status=1",
    'exit "$status"',
):
    if required not in guest_cleanup:
        raise SystemExit(
            "Linux Exit DNS UI guest cleanup does not preserve failures: "
            f"{required}"
        )
PY

python3 - \
  "$ROOT/linux/src/main/saved_networks.rs" \
  "$ROOT/scripts/desktop-mobile-manual-join-atspi.py" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
driver = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
for variable, selector in (
    ("mode", "nvpn-exit-dns-mode"),
    ("provider", "nvpn-exit-dns-provider"),
    ("custom_url", "nvpn-exit-dns-custom-url"),
    ("bootstrap_ips", "nvpn-exit-dns-bootstrap-ips"),
    ("through_servers", "nvpn-exit-dns-through-servers"),
    ("save", "nvpn-exit-dns-save"),
):
    exposure = f'selectors.expose_object("{selector}", &{variable});'
    if source.count(exposure) != 1:
        raise SystemExit(
            f"Linux Exit DNS control does not expose the exact stable GTK "
            f"buildable ID {selector}"
        )
if "set_dropdown_accessible_label" in source:
    raise SystemExit("Linux Exit DNS still duplicates selectors as dynamic labels")
for required in (
    'name.startswith("nvpn-exit-dns-")',
    "node.get_accessible_id() == name",
    "return ancestor_with_accessible_id(node, name)",
    '"nvpn-exit-dns-mode": (',
    '"Automatic (recommended)"',
    '"Encrypted DNS"',
    '"DNS through exit"',
    '"nvpn-exit-dns-provider": (',
    '"Cloudflare"',
    '"Quad9"',
    '"Custom DoH"',
    "def select_dns_index(name: str, index: int)",
    "def selected_dns_index(",
    "labels = DNS_DROPDOWN_LABELS[name]",
    "selected_dns_index(name, expected=index)",
    "canonical_ip_csv(",
    "observed_bootstrap",
    "self.args.dns_bootstrap_ips",
    "wait_dropdown_expanded(name, False)",
    "wait_dropdown_expanded(name, True)",
    "pyatspi.STATE_EXPANDED",
    "wait_dropdown_popup_ready(name)",
    "expected_items = len(DNS_DROPDOWN_LABELS[name])",
    'node.getRoleName() != "list box"',
    "def focused_actionable_nodes() -> list[Any]:",
    "def sole_focused_target(name: str) -> Any | None:",
    "saw_non_target_focus = False",
    "target = sole_focused_target(name)",
    "if focused and not any(focused_target(node, name) for node in focused):",
    "target_window_has_focus() and sole_focused_target(name) is not None",
    "def invoke_until_visible(name: str, expected: str, attempts: int = 4)",
    "except RuntimeError as error:",
    "invoke(name)\n",
    'subprocess.run(["xdotool", "key", "--clearmodifiers", "Escape"]',
):
    if required not in driver:
        raise SystemExit(
            "Linux Exit DNS AT-SPI driver does not match exact stable "
            f"accessible IDs: {required}"
        )

read_text_start = driver.index("def read_text(name: str) -> str:")
read_text_end = driver.index("\ndef read_npub(", read_text_start)
read_text = driver[read_text_start:read_text_end]
for required in (
    "deadline = time.monotonic() + 3",
    "for candidate in matching_nodes(name):",
    "candidate.queryText().getText(0, -1).strip()",
    "pyatspi.Registry.pumpQueuedEvents()",
):
    if required not in read_text:
        raise SystemExit(
            "Linux Exit DNS text read does not reacquire a fresh exact-ID "
            f"AT-SPI node after GTK replaces a stale object: {required}"
        )

for forbidden in ("doAction(", "grabFocus(", "querySelection(", "selectChild("):
    if forbidden in driver:
        raise SystemExit(
            f"Linux Exit DNS driver retains a fallback path: {forbidden}"
        )
PY

python3 - \
  "$ROOT/scripts/desktop-mobile-manual-join-windows-ui.ps1" \
  "$ROOT/scripts/windows-vm-exit-dns-ui-e2e.sh" <<'PY'
import pathlib
import sys

driver = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
matrix = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
start = driver.index("function Select-ComboItem {")
end = driver.index("function Read-ComboItem {", start)
selector = driver[start:end]

for required in (
    "[System.Windows.Automation.ItemContainerPattern]::Pattern",
    "$Container.FindItemByProperty(",
    "$null,",
    "[System.Windows.Automation.AutomationElement]::NameProperty,",
    "$Name",
    "[System.Windows.Automation.SelectionItemPattern]::Pattern",
    "$Pattern.Select()",
    "(Read-ComboItem $AutomationId) -ne $Name",
):
    if required not in selector:
        raise SystemExit(
            "Windows Exit DNS ComboBox selection is not canonical: "
            f"{required}"
        )

for forbidden in (
    ".FindAll(",
    "TreeScope]::Descendants",
    "SendKeys",
    "mouse_event",
    "SetCursorPos",
    "catch {",
    "continue",
):
    if forbidden in selector:
        raise SystemExit(
            "Windows Exit DNS ComboBox selection retains a fallback path: "
            f"{forbidden}"
        )

for required in (
    "@{ Case='cloudflare'; Mode='encrypted'; Provider='cloudflare';",
    "@{ Case='quad9'; Mode='encrypted'; Provider='quad9';",
    "@{ Case='custom'; Mode='encrypted'; Provider='custom';",
):
    if required not in matrix:
        raise SystemExit(
            "Windows Exit DNS real UI matrix lost provider transition: "
            f"{required}"
        )
PY

python3 - "$ROOT/scripts/macos-exit-dns-ax.swift" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
for required in (
    "func canonicalCSV(_ value: String) -> String",
    "canonicalCSV(observedBootstrap) == canonicalCSV(bootstrapIPs)",
    'values["bootstrapIps"] = bootstrapIPs',
):
    if required not in source:
        raise SystemExit(
            f"macOS Exit DNS driver lacks canonical CSV readback: {required}"
        )
PY

python3 - "$ROOT/scripts/release-network-evidence.py" <<'PY'
import importlib.util
import hashlib
import json
import pathlib
import shutil
import sys
import tempfile

spec = importlib.util.spec_from_file_location("release_network_evidence", sys.argv[1])
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

app_sha = "a" * 40
app_tree = "b" * 40
artifact_hash = "c" * 64
cli_hash = "d" * 64
settings = {
    "automatic": ("automatic", "cloudflare", "", "", ""),
    "cloudflare": ("encrypted", "cloudflare", "", "", ""),
    "quad9": ("encrypted", "quad9", "", "", ""),
    "custom": (
        "encrypted",
        "custom",
        "https://dns.google/dns-query",
        "8.8.8.8,8.8.4.4",
        "",
    ),
    "through-exit": ("through_exit", "cloudflare", "", "", "10.99.79.53"),
}


def write(root: pathlib.Path, platform: str) -> None:
    for case, values in settings.items():
        mode, provider, custom, bootstrap, through = values
        (root / f"{case}.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "mode": "DnsPolicy",
                    "publicUiOnly": True,
                    "privateStateRead": False,
                    "receiptSchema": 1,
                    "platform": platform,
                    "case": case,
                    "evidenceSource": "shipped-ui-restart-readback",
                    "savedViaShippedUi": True,
                    "uiRestartReadback": True,
                    "releaseBlackbox": True,
                    "exitDnsMode": mode,
                    "exitDnsDohProvider": provider,
                    "exitDnsCustomDohUrl": custom,
                    "exitDnsCustomDohBootstrapIps": bootstrap,
                    "exitDnsThroughExitServers": through,
                    "appGitSha": app_sha,
                    "appGitTree": app_tree,
                    "appExecutableSha256": artifact_hash,
                    "cliExecutableSha256": cli_hash,
                }
            )
            + "\n",
            encoding="utf-8-sig" if platform == "windows" else "utf-8",
        )


with tempfile.TemporaryDirectory() as temporary:
    base = pathlib.Path(temporary)
    for platform in ("linux", "macos", "windows"):
        root = base / platform
        root.mkdir()
        write(root, platform)
        cases, hashes, source, reused_hash = module.validate_desktop_dns_ui_receipts(
            root, platform, app_sha, app_tree
        )
        assert set(cases) == set(settings)
        assert set(hashes) == {f"{case}.json" for case in settings}
        assert source == (app_sha, app_tree)
        assert reused_hash is None

    seller_sidecar = base / "seller-sidecar"
    shutil.copytree(base / "macos", seller_sidecar)
    (seller_sidecar / "paid-exit-seller.json").write_text(
        json.dumps({"case": "paid-exit-seller"}) + "\n",
        encoding="utf-8",
    )
    cases, hashes, source, reused_hash = module.validate_desktop_dns_ui_receipts(
        seller_sidecar, "macos", app_sha, app_tree
    )
    assert set(cases) == set(settings)
    assert set(hashes) == {f"{case}.json" for case in settings}
    assert source == (app_sha, app_tree)
    assert reused_hash is None

    unexpected_sidecar = base / "unexpected-sidecar"
    shutil.copytree(base / "linux", unexpected_sidecar)
    (unexpected_sidecar / "unrelated.json").write_text(
        json.dumps({"case": "unrelated"}) + "\n",
        encoding="utf-8",
    )
    try:
        module.validate_desktop_dns_ui_receipts(
            unexpected_sidecar, "linux", app_sha, app_tree
        )
    except ValueError:
        pass
    else:
        raise SystemExit("unexpected desktop DNS UI sidecar was accepted")

    bad = base / "bad-bootstrap"
    shutil.copytree(base / "linux", bad)
    path = bad / "custom.json"
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    value["exitDnsCustomDohBootstrapIps"] = "1.1.1.1"
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    try:
        module.validate_desktop_dns_ui_receipts(
            bad, "linux", app_sha, app_tree
        )
    except ValueError:
        pass
    else:
        raise SystemExit("wrong custom bootstrap was accepted")

    mixed = base / "mixed-artifact"
    shutil.copytree(base / "windows", mixed)
    path = mixed / "quad9.json"
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    value["appExecutableSha256"] = "e" * 64
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    try:
        module.validate_desktop_dns_ui_receipts(
            mixed, "windows", app_sha, app_tree
        )
    except ValueError:
        pass
    else:
        raise SystemExit("mixed desktop app artifacts were accepted")

    private = base / "private-state"
    shutil.copytree(base / "macos", private)
    path = private / "automatic.json"
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    value["privateStateRead"] = True
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    try:
        module.validate_desktop_dns_ui_receipts(
            private, "macos", app_sha, app_tree
        )
    except ValueError:
        pass
    else:
        raise SystemExit("private-state desktop DNS evidence was accepted")

    reused = base / "reused-macos"
    cases_root = reused / "cases"
    cases_root.mkdir(parents=True)
    write(cases_root, "macos")
    receipt_sha = "e" * 40
    receipt_tree = "f" * 40
    proof = {
        "policy": "unchanged-platform-product-inputs-v1",
        "platform": "macos",
        "receipt_app_git_sha": receipt_sha,
        "receipt_app_git_tree": receipt_tree,
        "candidate_app_git_sha": app_sha,
        "candidate_app_git_tree": app_tree,
        "changed_paths_sha256": "1" * 64,
    }
    artifact = {
        "receiptSchema": 1,
        "appGitSha": receipt_sha,
        "appGitTree": receipt_tree,
        "appExecutableSha256": artifact_hash,
        "cliExecutableSha256": cli_hash,
        "componentInputProof": proof,
        "componentInputProofSha256": "2" * 64,
    }
    artifact_path = reused / "app-artifact.json"
    artifact_path.write_text(json.dumps(artifact) + "\n", encoding="utf-8")
    artifact_receipt_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    (reused / "driver-receipt.json").write_text(
        json.dumps(
            {
                "receiptSchema": 1,
                "appGitSha": receipt_sha,
                "appGitTree": receipt_tree,
                "appExecutableSha256": artifact_hash,
                "appArtifactReceiptSha256": artifact_receipt_hash,
                "harnessGitSha": app_sha,
                "harnessGitTree": app_tree,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    for path in cases_root.glob("*.json"):
        value = json.loads(path.read_text())
        value["appGitSha"] = receipt_sha
        value["appGitTree"] = receipt_tree
        value["appArtifactReceiptSha256"] = artifact_receipt_hash
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    cases, hashes, source, reused_hash = module.validate_desktop_dns_ui_receipts(
        cases_root, "macos", app_sha, app_tree
    )
    assert set(cases) == set(settings)
    assert set(hashes) == {f"{case}.json" for case in settings}
    assert source == (receipt_sha, receipt_tree)
    assert reused_hash == artifact_receipt_hash

    for label, mutate in (
        ("candidate", lambda value: value["componentInputProof"].update(
            candidate_app_git_sha="3" * 40
        )),
        ("proof", lambda value: value["componentInputProof"].update(
            changed_paths_sha256="invalid"
        )),
    ):
        tampered = base / f"tampered-{label}"
        shutil.copytree(reused, tampered)
        path = tampered / "app-artifact.json"
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        for case_path in (tampered / "cases").glob("*.json"):
            case_value = json.loads(case_path.read_text())
            case_value["appArtifactReceiptSha256"] = digest
            case_path.write_text(json.dumps(case_value) + "\n", encoding="utf-8")
        try:
            module.validate_desktop_dns_ui_receipts(
                tampered / "cases", "macos", app_sha, app_tree
            )
        except ValueError:
            pass
        else:
            raise SystemExit(f"tampered {label} component proof was accepted")

    bad_link = base / "bad-artifact-link"
    shutil.copytree(reused, bad_link)
    path = bad_link / "cases" / "automatic.json"
    value = json.loads(path.read_text())
    value["appArtifactReceiptSha256"] = "4" * 64
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    try:
        module.validate_desktop_dns_ui_receipts(
            bad_link / "cases", "macos", app_sha, app_tree
        )
    except ValueError:
        pass
    else:
        raise SystemExit("wrong macOS app artifact link was accepted")

    missing = base / "missing"
    shutil.copytree(base / "linux", missing)
    (missing / "through-exit.json").unlink()
    try:
        module.validate_desktop_dns_ui_receipts(
            missing, "linux", app_sha, app_tree
        )
    except ValueError:
        pass
    else:
        raise SystemExit("incomplete desktop DNS UI matrix was accepted")
PY

echo "DESKTOP_DNS_UI_EVIDENCE_CONTRACT_OK"
