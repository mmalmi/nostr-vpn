#!/usr/bin/env bash
# Build the Windows installer on an SSH-reachable Windows VM, install it, and
# verify NostrVpn.Windows starts and stays alive instead of exiting at startup.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/release_common.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/mobile_env.sh"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib-mobile-release-join-artifacts.sh"
load_release_env "$ROOT"
load_mobile_env "$ROOT"
release_join_require_clean_fips
release_join_assert_fips_unchanged
EXPECTED_FIPS_SHA="$RELEASE_JOIN_FIPS_SHA"
EXPECTED_FIPS_TREE="$RELEASE_JOIN_FIPS_TREE"
EXPECTED_FIPS_VERSION="$RELEASE_JOIN_FIPS_VERSION"
SSH_HOST="${NVPN_WINDOWS_SSH_HOST:-${1:-win11-dev}}"
SSH_JUMP="${NVPN_WINDOWS_SSH_JUMP:-}"
SSH_PROXY_COMMAND="${NVPN_WINDOWS_SSH_PROXY_COMMAND:-}"
GUEST_REPO="${NVPN_WINDOWS_GUEST_REPO_PATH:-C:\\src\\nostr-vpn}"
GUEST_FIPS_REPO="${NVPN_WINDOWS_GUEST_FIPS_REPO_PATH:-C:\\src\\fips}"
GUEST_ARTIFACT_ROOT="${GUEST_ARTIFACT_ROOT:-C:\\src\\nostr-vpn\\artifacts}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-$ROOT/artifacts}"
VERSION="$(
  awk '
    $0 == "[workspace.package]" { package = 1; next }
    package && /^\[/ { exit }
    package && /^version = "/ {
      value = $0
      sub(/^version = "/, "", value)
      sub(/".*$/, "", value)
      print value
      exit
    }
  ' "$ROOT/Cargo.toml"
)"
SMOKE_TAG="${NVPN_WINDOWS_APP_SMOKE_TAG:-v$VERSION}"
LOCAL_GATE_DIR="${NVPN_WINDOWS_INSTALLER_GATE_ARTIFACT_DIR:-$ARTIFACT_ROOT/windows-installer-gate}"
PRESEALED_SOURCE_FIPS_RECEIPT="${NVPN_WINDOWS_PRESEALED_SOURCE_FIPS_RECEIPT_PATH:-}"
REMOTE_GATE_DIR="$GUEST_ARTIFACT_ROOT\\windows-installer-gate"

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ \
  && "$SMOKE_TAG" == "v$VERSION" ]] || {
  echo "Windows installer smoke tag must exactly match workspace version v$VERSION" >&2
  exit 2
}
mkdir -p "$LOCAL_GATE_DIR"

ssh_command() {
  SSH_CMD=(ssh -o BatchMode=yes)
  if [[ -n "$SSH_PROXY_COMMAND" ]]; then
    SSH_CMD+=(-o "ProxyCommand=$SSH_PROXY_COMMAND")
  elif [[ -n "$SSH_JUMP" ]]; then
    SSH_CMD+=(-J "$SSH_JUMP")
  fi
  SSH_CMD+=("$SSH_HOST")
}

scp_command() {
  SCP_CMD=(scp -q -o BatchMode=yes -o ConnectTimeout=10)
  if [[ -n "$SSH_PROXY_COMMAND" ]]; then
    SCP_CMD+=(-o "ProxyCommand=$SSH_PROXY_COMMAND")
  elif [[ -n "$SSH_JUMP" ]]; then
    SCP_CMD+=(-J "$SSH_JUMP")
  fi
}

run_ps() {
  local script="$1"
  local encoded
  encoded="$(printf '%s' "$script" | iconv -t UTF-16LE | base64 | tr -d '\n')"
  ssh_command
  "${SSH_CMD[@]}" powershell.exe -NoProfile -EncodedCommand "$encoded"
}

case "${NVPN_WINDOWS_SKIP_GIT_SYNC:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On)
    echo "Skipping Windows VM git sync; release-gate lane already synced the candidate."
    ;;
  *)
    "$ROOT/scripts/windows-vm-git-sync.sh" "$SSH_HOST"
    ;;
esac

run_ps "\$ErrorActionPreference = 'Stop'
Set-Location '$GUEST_REPO'
New-Item -ItemType Directory -Force -Path '$GUEST_ARTIFACT_ROOT' | Out-Null
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue '$REMOTE_GATE_DIR'
New-Item -ItemType Directory -Force -Path '$REMOTE_GATE_DIR' | Out-Null
if ('${NVPN_FIPS_REPO_PATH:-}' -ne '') { \$env:NVPN_FIPS_REPO_PATH = '$GUEST_FIPS_REPO' }
\$fipsHead = (git -C '$GUEST_FIPS_REPO' rev-parse HEAD).Trim()
\$fipsTree = (git -C '$GUEST_FIPS_REPO' rev-parse 'HEAD^{tree}').Trim()
\$fipsStatus = (git -C '$GUEST_FIPS_REPO' status --porcelain --untracked-files=all | Out-String).Trim()
if (
  \$fipsHead -ne '$EXPECTED_FIPS_SHA' -or
  \$fipsTree -ne '$EXPECTED_FIPS_TREE' -or
  \$fipsStatus
) {
  throw 'Windows installer build FIPS checkout differs from the exact release candidate'
}
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\installer\windows-installer-migrate.tests.ps1
if (\$LASTEXITCODE -ne 0) { throw ('Windows installer migration unit test failed with exit code {0}' -f \$LASTEXITCODE) }
\$env:CARGO_TARGET_DIR = Join-Path '$GUEST_ARTIFACT_ROOT' 'windows-smoke-cargo'
\$targetPrefix = [IO.Path]::GetFullPath(\$env:CARGO_TARGET_DIR).TrimEnd([char]92) + [char]92
Get-CimInstance Win32_Process -Filter \"Name = 'nvpn.exe'\" |
  Where-Object {
    \$_.ExecutablePath -and
    [IO.Path]::GetFullPath(\$_.ExecutablePath).StartsWith(\$targetPrefix, [StringComparison]::OrdinalIgnoreCase)
  } |
  ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction Stop }
Get-Process -Name NostrVpn.Windows -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction Stop
\$installer = Join-Path '$REMOTE_GATE_DIR' 'nostr-vpn-$SMOKE_TAG-windows-x64-setup.exe'
Remove-Item -Force \$installer -ErrorAction SilentlyContinue
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\windows-build.ps1 -Configuration Release -Installer -Tag '$SMOKE_TAG' -OutputDir '$REMOTE_GATE_DIR'
if (\$LASTEXITCODE -ne 0) { throw ('windows-build.ps1 failed with exit code {0}' -f \$LASTEXITCODE) }
if (!(Test-Path \$installer)) { throw ('Windows installer was not created: {0}' -f \$installer) }
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\windows-installer-smoke.ps1 -InstallerPath \$installer -ArtifactRoot (Join-Path '$REMOTE_GATE_DIR' 'smoke')
if (\$LASTEXITCODE -ne 0) { throw ('windows-installer-smoke.ps1 failed with exit code {0}' -f \$LASTEXITCODE) }
\$candidate = Join-Path \$env:CARGO_TARGET_DIR 'release\\nvpn.exe'
\$embeddedFips = (& \$candidate version --verbose | Out-String)
if (\$LASTEXITCODE -ne 0) {
  throw ('nvpn version --verbose failed with exit code {0}' -f \$LASTEXITCODE)
}
if (!\$embeddedFips.Contains('(rev ${EXPECTED_FIPS_SHA:0:10})')) {
  throw 'Windows installer payload does not embed the exact FIPS revision'
}
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\windows-daemon-idle-cpu.ps1 -Bin \$candidate -ArtifactRoot (Join-Path '$REMOTE_GATE_DIR' 'daemon-idle')
if (\$LASTEXITCODE -ne 0) { throw ('windows-daemon-idle-cpu.ps1 failed with exit code {0}' -f \$LASTEXITCODE) }
\$smokePath = Join-Path '$REMOTE_GATE_DIR' 'smoke\\windows-app-launch-smoke.json'
\$smoke = Get-Content -Raw -LiteralPath \$smokePath | ConvertFrom-Json
if (\$smoke.ok -ne \$true) { throw 'exact installer app launch receipt did not pass' }
\$head = (git rev-parse HEAD).Trim()
\$tree = (git rev-parse 'HEAD^{tree}').Trim()
\$status = (git status --porcelain --untracked-files=all | Out-String).Trim()
if (\$status) { throw 'Windows installer build changed the exact source checkout' }
\$publish = Join-Path '$GUEST_REPO' 'windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish'
\$payloads = [ordered]@{}
\$payloadFiles = [ordered]@{
  app = [ordered]@{ file = 'NostrVpn.Windows.exe'; path = (Join-Path \$publish 'NostrVpn.Windows.exe') }
  appCore = [ordered]@{ file = 'nostr_vpn_app_core.dll'; path = (Join-Path \$publish 'nostr_vpn_app_core.dll') }
  cli = [ordered]@{ file = 'nvpn.exe'; path = (Join-Path \$publish 'nvpn.exe') }
  wintun = [ordered]@{ file = 'binaries\\wintun.dll'; path = (Join-Path \$publish 'binaries\\wintun.dll') }
}
foreach (\$entry in \$payloadFiles.GetEnumerator()) {
  if (!(Test-Path -LiteralPath \$entry.Value.path -PathType Leaf)) {
    throw ('Windows installer payload is missing: ' + \$entry.Key)
  }
  \$installed = \$smoke.installedPayloads.(\$entry.Key)
  if (
    \$null -eq \$installed -or
    \$installed.file -cne \$entry.Value.file
  ) {
    throw ('Windows installer smoke mislabeled its installed payload: ' + \$entry.Key)
  }
  \$publishHash = (Get-FileHash -Algorithm SHA256 -LiteralPath \$entry.Value.path).Hash.ToLowerInvariant()
  \$publishSize = (Get-Item -LiteralPath \$entry.Value.path).Length
  if (
    \$installed.sha256 -ne \$publishHash -or
    [long]\$installed.size -ne [long]\$publishSize
  ) {
    throw ('Sealed Windows installer payload differs from the publish directory: ' + \$entry.Key)
  }
  \$payloads[\$entry.Key] = [ordered]@{
    file = \$installed.file
    sha256 = \$installed.sha256
    size = [long]\$installed.size
  }
}
# Package only the payloads just matched to the installed app. Publication must
# not rebuild the CLI or depend on the guest publish directory remaining intact.
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
\$cliArchive = Join-Path '$REMOTE_GATE_DIR' 'nvpn-$SMOKE_TAG-x86_64-pc-windows-msvc.zip'
\$zip = [IO.Compression.ZipFile]::Open(\$cliArchive, [IO.Compression.ZipArchiveMode]::Create)
try {
  foreach (\$name in @('cli', 'wintun')) {
    \$payload = \$payloadFiles[\$name]
    \$entry = \$zip.CreateEntry(\$payload.file.Replace([char]92, [char]47))
    \$entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    \$inputStream = [IO.File]::OpenRead(\$payload.path)
    try {
      \$outputStream = \$entry.Open()
      try { \$inputStream.CopyTo(\$outputStream) } finally { \$outputStream.Dispose() }
    } finally {
      \$inputStream.Dispose()
    }
  }
} finally {
  \$zip.Dispose()
}
\$receipt = [ordered]@{
  receiptSchema = 2
  platform = 'windows'
  artifactType = 'exact installed Windows Release setup'
  appGitSha = \$head
  appGitTree = \$tree
  fipsGitSha = \$fipsHead
  fipsGitTree = \$fipsTree
  fipsVersion = '$EXPECTED_FIPS_VERSION'
  tag = '$SMOKE_TAG'
  installerName = (Split-Path -Leaf \$installer)
  installerSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath \$installer).Hash.ToLowerInvariant()
  installerSize = (Get-Item -LiteralPath \$installer).Length
  installerInstalledAndLaunched = \$true
  installedAppStayedAlive = \$true
  smokeReceiptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath \$smokePath).Hash.ToLowerInvariant()
  payloads = \$payloads
  builtOnWindowsVm = \$true
  builtOnHostMac = \$false
}
\$receipt | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -LiteralPath (Join-Path '$REMOTE_GATE_DIR' 'installer-receipt.json')
exit \$LASTEXITCODE"

rm -rf "$LOCAL_GATE_DIR"
mkdir -p "$LOCAL_GATE_DIR"
scp_command
remote_gate_posix="${REMOTE_GATE_DIR//\\//}"
"${SCP_CMD[@]}" \
  "$SSH_HOST:$remote_gate_posix/nostr-vpn-$SMOKE_TAG-windows-x64-setup.exe" \
  "$LOCAL_GATE_DIR/nostr-vpn-$SMOKE_TAG-windows-x64-setup.exe"
"${SCP_CMD[@]}" \
  "$SSH_HOST:$remote_gate_posix/installer-receipt.json" \
  "$LOCAL_GATE_DIR/installer-receipt.json"
"${SCP_CMD[@]}" \
  "$SSH_HOST:$remote_gate_posix/nvpn-$SMOKE_TAG-x86_64-pc-windows-msvc.zip" \
  "$LOCAL_GATE_DIR/nvpn-$SMOKE_TAG-x86_64-pc-windows-msvc.zip"
python3 - \
  "$LOCAL_GATE_DIR/installer-receipt.json" \
  "$LOCAL_GATE_DIR/nostr-vpn-$SMOKE_TAG-windows-x64-setup.exe" \
  "$(git -C "$ROOT" rev-parse HEAD)" \
  "$(git -C "$ROOT" rev-parse 'HEAD^{tree}')" \
  "$EXPECTED_FIPS_SHA" \
  "$EXPECTED_FIPS_TREE" \
  "$EXPECTED_FIPS_VERSION" \
  "$SMOKE_TAG" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
import zipfile

receipt_path = pathlib.Path(sys.argv[1])
installer_path = pathlib.Path(sys.argv[2])
commit, tree, fips_commit, fips_tree, fips_version, tag = sys.argv[3:]
receipt = json.loads(receipt_path.read_text(encoding="utf-8-sig"))
digest = hashlib.sha256(installer_path.read_bytes()).hexdigest()
if not (
    receipt.get("receiptSchema") == 2
    and receipt.get("platform") == "windows"
    and receipt.get("artifactType") == "exact installed Windows Release setup"
    and receipt.get("appGitSha") == commit
    and receipt.get("appGitTree") == tree
    and receipt.get("fipsGitSha") == fips_commit
    and receipt.get("fipsGitTree") == fips_tree
    and receipt.get("fipsVersion") == fips_version
    and receipt.get("tag") == tag
    and receipt.get("installerName") == installer_path.name
    and receipt.get("installerSha256") == digest
    and receipt.get("installerSize") == installer_path.stat().st_size
    and receipt.get("installerInstalledAndLaunched") is True
    and receipt.get("installedAppStayedAlive") is True
    and receipt.get("builtOnWindowsVm") is True
    and receipt.get("builtOnHostMac") is False
    and re.fullmatch(r"[0-9a-f]{64}", receipt.get("smokeReceiptSha256", ""))
):
    raise SystemExit("pulled Windows installer receipt is incomplete")
payloads = receipt.get("payloads", {})
if set(payloads) != {"app", "appCore", "cli", "wintun"}:
    raise SystemExit("Windows installer receipt has the wrong payload set")
expected_files = {
    "app": "NostrVpn.Windows.exe",
    "appCore": "nostr_vpn_app_core.dll",
    "cli": "nvpn.exe",
    "wintun": r"binaries\wintun.dll",
}
for name, value in payloads.items():
    if not (
        value.get("file") == expected_files[name]
        and
        re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", "")))
        and isinstance(value.get("size"), int)
        and value["size"] > 0
    ):
        raise SystemExit(f"Windows installer receipt has invalid {name} payload")
archive_path = receipt_path.parent / f"nvpn-{tag}-x86_64-pc-windows-msvc.zip"
with zipfile.ZipFile(archive_path) as archive:
    if sorted(archive.namelist()) != ["binaries/wintun.dll", "nvpn.exe"]:
        raise SystemExit("Windows CLI archive has the wrong payload set")
    for name in ("cli", "wintun"):
        payload = payloads[name]
        data = archive.read(payload["file"].replace("\\", "/"))
        if len(data) != payload["size"] or hashlib.sha256(data).hexdigest() != payload["sha256"]:
            raise SystemExit(f"Windows CLI archive differs from installed {name} payload")
PY

SOURCE_FIPS_RECEIPT="$LOCAL_GATE_DIR/cratesio-source-receipt.json"
if [[ -n "$PRESEALED_SOURCE_FIPS_RECEIPT" ]]; then
  if [[ ! -f "$PRESEALED_SOURCE_FIPS_RECEIPT" \
    || -L "$PRESEALED_SOURCE_FIPS_RECEIPT" \
    || ! -r "$PRESEALED_SOURCE_FIPS_RECEIPT" ]]
  then
    echo "Presealed Windows crates.io source receipt is not a readable regular file." >&2
    exit 1
  fi
  cp "$PRESEALED_SOURCE_FIPS_RECEIPT" "$SOURCE_FIPS_RECEIPT"
else
  node "$ROOT/scripts/release-source-verification.mjs" \
    windows-cratesio-source-receipt \
    "$(git -C "$ROOT" rev-parse HEAD)" \
    "$(git -C "$ROOT" rev-parse 'HEAD^{tree}')" \
    "$NVPN_FIPS_REPO_PATH" \
    "$EXPECTED_FIPS_SHA" \
    "$EXPECTED_FIPS_TREE" \
    "$EXPECTED_FIPS_VERSION" \
    >"$SOURCE_FIPS_RECEIPT"
fi
node "$ROOT/scripts/release-source-verification.mjs" \
  windows-cratesio-provenance \
  "$SOURCE_FIPS_RECEIPT" \
  "$LOCAL_GATE_DIR/installer-receipt.json" \
  "$(git -C "$ROOT" rev-parse HEAD)" \
  "$(git -C "$ROOT" rev-parse 'HEAD^{tree}')" \
  "$NVPN_FIPS_REPO_PATH" \
  "$EXPECTED_FIPS_SHA" \
  "$EXPECTED_FIPS_TREE" \
  "$EXPECTED_FIPS_VERSION" \
  >"$LOCAL_GATE_DIR/cratesio-provenance-validation.json"

release_join_assert_fips_unchanged
echo "WINDOWS_VM_APP_LAUNCH_SMOKE_OK"
