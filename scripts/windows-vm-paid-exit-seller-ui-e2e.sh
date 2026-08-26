#!/usr/bin/env bash
# Drive paid-exit seller settings through the exact installed Windows Release app.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_HOST="${NVPN_WINDOWS_SSH_HOST:-${1:-}}"
SSH_JUMP="${NVPN_WINDOWS_SSH_JUMP:-}"
SSH_PROXY_COMMAND="${NVPN_WINDOWS_SSH_PROXY_COMMAND:-}"
GUEST_REPO="${NVPN_WINDOWS_GUEST_REPO_PATH:-C:\\src\\nostr-vpn}"
GUEST_ARTIFACT_ROOT="${GUEST_ARTIFACT_ROOT:-C:\\src\\nostr-vpn\\artifacts}"
LOCAL_ARTIFACT_DIR="${NVPN_PAID_EXIT_SELLER_UI_ARTIFACT_DIR:-$ROOT/artifacts/paid-exit-seller-ui/windows}"
[[ -n "$SSH_HOST" ]] || {
  echo "set NVPN_WINDOWS_SSH_HOST or pass the Windows VM SSH target" >&2
  exit 2
}
app_sha="$(git -C "$ROOT" rev-parse HEAD)"
app_tree="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"

ssh_command() {
  SSH_CMD=(ssh -o BatchMode=yes -o ConnectTimeout=10)
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
  local encoded
  encoded="$(printf '%s' "$1" | iconv -t UTF-16LE | base64 | tr -d '\n')"
  ssh_command
  "${SSH_CMD[@]}" powershell.exe -NoProfile -EncodedCommand "$encoded"
}

case "${NVPN_WINDOWS_SKIP_GIT_SYNC:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
  *) "$ROOT/scripts/windows-vm-git-sync.sh" "$SSH_HOST" ;;
esac

run_ps "\$ErrorActionPreference = 'Stop'
Set-Location '$GUEST_REPO'
\$appSha = (git rev-parse HEAD).Trim()
\$appTree = (git rev-parse 'HEAD^{tree}').Trim()
if (\$appSha -ne '$app_sha' -or \$appTree -ne '$app_tree') {
  throw 'Windows seller UI checkout differs from the exact host candidate'
}
if (git status --porcelain --untracked-files=all) {
  throw 'Windows seller UI gate refuses a dirty source checkout'
}
\$artifact = Join-Path '$GUEST_ARTIFACT_ROOT' 'windows-paid-exit-seller-ui'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \$artifact
New-Item -ItemType Directory -Force -Path \$artifact | Out-Null
\$installerReceiptPath = Join-Path '$GUEST_ARTIFACT_ROOT' 'windows-installer-gate\\installer-receipt.json'
\$app = Join-Path '$GUEST_REPO' 'windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish\\NostrVpn.Windows.exe'
\$cli = Join-Path (Split-Path -Parent \$app) 'nvpn.exe'
if (!(Test-Path \$installerReceiptPath) -or !(Test-Path \$app) -or !(Test-Path \$cli)) {
  throw 'exact smoke-gated Windows installer app/CLI is missing'
}
\$installerReceipt = Get-Content -Raw \$installerReceiptPath | ConvertFrom-Json
\$expectedAppHash = \$installerReceipt.payloads.app.sha256
\$expectedCliHash = \$installerReceipt.payloads.cli.sha256
if (
  \$installerReceipt.installerInstalledAndLaunched -ne \$true -or
  (Get-FileHash -Algorithm SHA256 \$app).Hash.ToLowerInvariant() -ne \$expectedAppHash -or
  (Get-FileHash -Algorithm SHA256 \$cli).Hash.ToLowerInvariant() -ne \$expectedCliHash
) { throw 'Windows seller UI app/CLI differs from the installed-and-launched payload' }
\$wrapper = Join-Path \$artifact 'interactive.ps1'
@'
\$ErrorActionPreference = 'Stop'
\$artifact = '$GUEST_ARTIFACT_ROOT\\windows-paid-exit-seller-ui'
\$data = Join-Path \$artifact 'data'
New-Item -ItemType Directory -Force -Path \$data | Out-Null
\$arguments = @{
  Mode = 'PaidExitSeller'
  AppExe = '$GUEST_REPO\\windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish\\NostrVpn.Windows.exe'
  CliExe = '$GUEST_REPO\\windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish\\nvpn.exe'
  DataDir = \$data
  MarkerPath = (Join-Path \$artifact 'receipt.json')
  SellerPrice = '1000000'
  SellerCountry = 'FI'
  SellerMint = 'http://cashu-mint:3338'
  AppGitSha = '$app_sha'
  AppGitTree = '$app_tree'
}
& '$GUEST_REPO\\scripts\\desktop-mobile-manual-join-windows-ui.ps1' @arguments
if (!\$?) { throw 'shipped Windows paid-exit seller UI failed' }
'@ | Set-Content -Encoding utf8 \$wrapper
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\run-windows-interactive-e2e.ps1 -ScriptPath \$wrapper -TimeoutSeconds 120
if (\$LASTEXITCODE -ne 0) { throw 'interactive Windows seller UI e2e failed' }
\$value = Get-Content -Raw (Join-Path \$artifact 'receipt.json') | ConvertFrom-Json
if (
  \$value.receiptSchema -ne 1 -or \$value.platform -ne 'windows' -or
  \$value.case -ne 'paid-exit-seller' -or \$value.savedViaShippedUi -ne \$true -or
  \$value.enabledViaShippedUi -ne \$true -or \$value.uiRestartReadback -ne \$true -or
  \$value.privateStateRead -ne \$false -or \$value.paidExitEnabled -ne \$true -or
  \$value.paidExitPriceMsatPerGb -ne 1000000 -or \$value.paidExitCountryCode -ne 'FI' -or
  \$value.paidExitAcceptedMints.Count -ne 1 -or
  \$value.paidExitAcceptedMints[0] -ne 'http://cashu-mint:3338' -or
  \$value.appGitSha -ne \$appSha -or \$value.appGitTree -ne \$appTree -or
  \$value.appExecutableSha256 -ne \$expectedAppHash -or
  \$value.cliExecutableSha256 -ne \$expectedCliHash
) { throw 'invalid Windows paid-exit seller UI receipt' }
Compress-Archive -Force -Path (Join-Path \$artifact '*') -DestinationPath (Join-Path \$artifact 'evidence.zip')"

rm -rf "$LOCAL_ARTIFACT_DIR"
mkdir -p "$LOCAL_ARTIFACT_DIR"
scp_command
remote_zip="${GUEST_ARTIFACT_ROOT//\\//}/windows-paid-exit-seller-ui/evidence.zip"
"${SCP_CMD[@]}" "$SSH_HOST:$remote_zip" "$LOCAL_ARTIFACT_DIR/evidence.zip"
ditto -x -k "$LOCAL_ARTIFACT_DIR/evidence.zip" "$LOCAL_ARTIFACT_DIR"
rm -f "$LOCAL_ARTIFACT_DIR/evidence.zip"

echo "WINDOWS_VM_PAID_EXIT_SELLER_UI_E2E_OK"
