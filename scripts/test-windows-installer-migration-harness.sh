#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT" <<'PY'
import pathlib
import sys
import hashlib
import json
import subprocess
import tempfile
import zipfile

root = pathlib.Path(sys.argv[1])
installer = (root / "scripts/windows-installer.iss").read_text(encoding="utf-8")
migration = (root / "windows/installer/windows-installer-migrate.ps1").read_text(encoding="utf-8")
tests = (root / "windows/installer/windows-installer-migrate.tests.ps1").read_text(encoding="utf-8")
view_model = (root / "windows/NostrVpn.Windows/ViewModels/AppViewModel.cs").read_text(encoding="utf-8")
service_e2e = (root / "scripts/e2e-windows-service-toggle.ps1").read_text(encoding="utf-8")
windows_smoke = (root / "scripts/windows-vm-app-launch-smoke.sh").read_text(encoding="utf-8")
installer_smoke = (root / "scripts/windows-installer-smoke.ps1").read_text(encoding="utf-8")

required_installer = (
    "CloseApplicationsFilter=NostrVpn.Windows.exe,nostr-vpn-gui.exe",
    "Flags: dontcopy",
    "function PrepareToInstall",
    "ewWaitUntilTerminated",
    "ResultCode <> 0",
    "avoid installing a second copy",
)
for value in required_installer:
    if value not in installer:
        raise SystemExit(f"installer migration integration is missing: {value}")

required_migration = (
    "HKEY_LOCAL_MACHINE",
    "WOW6432Node",
    "HKEY_CURRENT_USER",
    "nostr-vpn-gui.exe",
    "NostrVpn.Windows.exe",
    "Resolve-NvpnOwnedRegistration",
    "Invoke-NvpnOwnedUninstall",
    "RequiresElevation",
    "Refusing an uninstaller outside",
    "registration survived its uninstaller",
    "executable survived its uninstaller",
)
for value in required_migration:
    if value not in migration:
        raise SystemExit(f"installer migration implementation is missing: {value}")

for value in (
    "Program Files\\Nostr VPN",
    "LocalAppData\\Programs\\Nostr VPN",
    "Roaming\\Nostr VPN",
    "Migration changed roaming config data",
    "outside legacy uninstaller",
    "failed current uninstaller",
):
    if value not in tests:
        raise SystemExit(f"seeded migration test is missing: {value}")

if "CanToggleVpn(" not in view_model:
    raise SystemExit("ToggleVpnCommand does not use the focused policy")
expression = "hasRuntimeActiveNetwork || (serviceSupported && !serviceInstalled)"
if expression not in view_model:
    raise SystemExit("ToggleVpnCommand still requires an active network when the service is missing")

def can_toggle(in_flight, supported, has_network, service_supported, installed):
    return (
        not in_flight
        and supported
        and (has_network or (service_supported and not installed))
    )

cases = (
    ((False, True, False, True, False), True, "missing service without network"),
    ((False, True, True, True, True), True, "installed service with network"),
    ((False, True, False, True, True), False, "installed service without network"),
    ((True, True, False, True, False), False, "action already running"),
    ((False, False, False, True, False), False, "VPN control unsupported"),
)
for inputs, expected, label in cases:
    actual = can_toggle(*inputs)
    if actual is not expected:
        raise SystemExit(f"toggle policy failed {label}: {actual} != {expected}")

if "desktop_roster_e2e_fixture" in service_e2e:
    raise SystemExit("service-toggle E2E still seeds an active network")
for value in (
    "New-Item -ItemType Directory -Force -Path $DataDir",
    "if (!$Toggle.Current.IsEnabled)",
    "supported service is missing",
):
    if value not in service_e2e:
        raise SystemExit(f"service-toggle no-network E2E is missing: {value}")

if "windows-installer-migrate.tests.ps1" not in windows_smoke:
    raise SystemExit("Windows artifact lane does not run the migration unit test")

for value in (
    "installedPayloads",
    "nostr_vpn_app_core.dll",
    "Get-FileHash -Algorithm SHA256",
):
    if value not in installer_smoke:
        raise SystemExit(f"installer smoke does not receipt installed payload: {value}")
for value in (
    "receiptSchema = 2",
    "Windows installer smoke mislabeled its installed payload",
    "Sealed Windows installer payload differs from the publish directory",
    '"appCore": "nostr_vpn_app_core.dll"',
):
    if value not in windows_smoke:
        raise SystemExit(f"Windows artifact receipt is not sealed-payload-bound: {value}")

for value in (
    "[IO.Compression.ZipArchiveMode]::Create",
    '"$SSH_HOST:$remote_gate_posix/nvpn-$SMOKE_TAG-x86_64-pc-windows-msvc.zip"',
):
    if value not in windows_smoke:
        raise SystemExit(f"Windows gate does not retain its tested CLI archive: {value}")

# Run the actual host-side receipt/ZIP validator on valid and tampered exports.
validation = windows_smoke.split('<<\'PY\'\n', 1)[1].split('\nPY\n', 1)[0]
with tempfile.TemporaryDirectory(prefix="nvpn-windows-retention-") as temporary:
    directory = pathlib.Path(temporary)
    installer_path = directory / "nostr-vpn-v4.1.10-windows-x64-setup.exe"
    installer_path.write_bytes(b"installer")
    archive = directory / "nvpn-v4.1.10-x86_64-pc-windows-msvc.zip"
    payloads = {
        "app": ("NostrVpn.Windows.exe", b"app"),
        "appCore": ("nostr_vpn_app_core.dll", b"core"),
        "cli": ("nvpn.exe", b"cli"),
        "wintun": (r"binaries\wintun.dll", b"wintun"),
    }
    receipt = {
        "receiptSchema": 2, "platform": "windows",
        "artifactType": "exact installed Windows Release setup",
        "appGitSha": "a" * 40, "appGitTree": "b" * 40,
        "fipsGitSha": "c" * 40, "fipsGitTree": "d" * 40,
        "fipsVersion": "0.4.73", "tag": "v4.1.10",
        "installerName": installer_path.name,
        "installerSha256": hashlib.sha256(b"installer").hexdigest(),
        "installerSize": 9, "installerInstalledAndLaunched": True,
        "installedAppStayedAlive": True, "builtOnWindowsVm": True,
        "builtOnHostMac": False, "smokeReceiptSha256": "e" * 64,
        "payloads": {
            name: {"file": filename, "size": len(data),
                   "sha256": hashlib.sha256(data).hexdigest()}
            for name, (filename, data) in payloads.items()
        },
    }
    receipt_path = directory / "installer-receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    for case in ("valid", "tampered-cli", "missing-wintun", "extra-member"):
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("nvpn.exe", b"wrong" if case == "tampered-cli" else b"cli")
            if case != "missing-wintun":
                output.writestr("binaries/wintun.dll", b"wintun")
            if case == "extra-member":
                output.writestr("unexpected.exe", b"extra")
        result = subprocess.run(
            [sys.executable, "-", str(receipt_path), str(installer_path),
             "a" * 40, "b" * 40, "c" * 40, "d" * 40, "0.4.73", "v4.1.10"],
            input=validation, text=True, capture_output=True,
        )
        if (result.returncode == 0) != (case == "valid"):
            raise SystemExit(f"Windows CLI export validation failed {case}: {result.stderr}")

print("WINDOWS_INSTALLER_MIGRATION_SOURCE_HARNESS_OK")
PY
