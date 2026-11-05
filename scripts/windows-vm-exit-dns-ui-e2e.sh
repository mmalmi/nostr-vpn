#!/usr/bin/env bash
# Drive every Exit DNS policy through the exact native Windows Release app.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_HOST="${NVPN_WINDOWS_SSH_HOST:-${1:-}}"
SSH_JUMP="${NVPN_WINDOWS_SSH_JUMP:-}"
SSH_PROXY_COMMAND="${NVPN_WINDOWS_SSH_PROXY_COMMAND:-}"
GUEST_REPO="${NVPN_WINDOWS_GUEST_REPO_PATH:-C:\\src\\nostr-vpn}"
GUEST_ARTIFACT_ROOT="${GUEST_ARTIFACT_ROOT:-C:\\src\\nostr-vpn\\artifacts}"
LOCAL_ARTIFACT_DIR="${NVPN_DESKTOP_DNS_UI_ARTIFACT_DIR:-$ROOT/artifacts/desktop-dns-ui/windows}"
[[ -n "$SSH_HOST" ]] || {
  echo "set NVPN_WINDOWS_SSH_HOST or pass the Windows VM SSH target" >&2
  exit 2
}
RELEASE_APP_ROOT="${NVPN_RELEASE_APP_REPO_PATH:-$ROOT}"
app_sha="$(git -C "$RELEASE_APP_ROOT" rev-parse HEAD)"
app_tree="$(git -C "$RELEASE_APP_ROOT" rev-parse 'HEAD^{tree}')"
[[ "$app_sha" =~ ^[0-9a-f]{40}$ && "$app_tree" =~ ^[0-9a-f]{40}$ ]] || {
  echo "could not resolve the exact Windows candidate source" >&2
  exit 2
}

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
  local script="$1"
  local encoded
  encoded="$(printf '%s' "$script" | iconv -t UTF-16LE | base64 | tr -d '\n')"
  ssh_command
  "${SSH_CMD[@]}" powershell.exe -NoProfile -EncodedCommand "$encoded"
}

case "${NVPN_WINDOWS_SKIP_GIT_SYNC:-0}" in
  1|true|TRUE|True|yes|YES|Yes|on|ON|On) ;;
  *) NVPN_WINDOWS_GIT_SYNC_EXACT_APP_COMMIT="$app_sha" \
     "$ROOT/scripts/windows-vm-git-sync.sh" "$SSH_HOST" ;;
esac

run_ps "\$ErrorActionPreference = 'Stop'
Set-Location '$GUEST_REPO'
\$appSha = (git rev-parse HEAD).Trim()
\$appTree = (git rev-parse 'HEAD^{tree}').Trim()
if (\$appSha -ne '$app_sha' -or \$appTree -ne '$app_tree') {
  throw 'Windows DNS UI checkout differs from the exact host candidate'
}
if (git status --porcelain --untracked-files=all) {
  throw 'Windows DNS UI gate refuses a dirty source checkout'
}
\$artifact = Join-Path '$GUEST_ARTIFACT_ROOT' 'windows-exit-dns-ui'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue \$artifact
New-Item -ItemType Directory -Force -Path \$artifact | Out-Null
\$installerReceiptPath = Join-Path '$GUEST_ARTIFACT_ROOT' 'windows-installer-gate\\installer-receipt.json'
\$app = Join-Path '$GUEST_REPO' 'windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish\\NostrVpn.Windows.exe'
\$cli = Join-Path (Split-Path -Parent \$app) 'nvpn.exe'
if (
  !(Test-Path -LiteralPath \$installerReceiptPath -PathType Leaf) -or
  !(Test-Path -LiteralPath \$app -PathType Leaf) -or
  !(Test-Path -LiteralPath \$cli -PathType Leaf)
) {
  throw 'exact smoke-gated Windows installer app/CLI is missing'
}
\$installerReceipt = Get-Content -Raw -LiteralPath \$installerReceiptPath | ConvertFrom-Json
\$expectedAppHash = \$installerReceipt.payloads.app.sha256
\$expectedCliHash = \$installerReceipt.payloads.cli.sha256
if (
  \$installerReceipt.installerInstalledAndLaunched -ne \$true -or
  (Get-FileHash -Algorithm SHA256 -LiteralPath \$app).Hash.ToLowerInvariant() -ne \$expectedAppHash -or
  (Get-FileHash -Algorithm SHA256 -LiteralPath \$cli).Hash.ToLowerInvariant() -ne \$expectedCliHash
) {
  throw 'Windows DNS UI app/CLI differs from the exact installed-and-launched installer payload'
}
\$wrapper = Join-Path \$artifact 'interactive.ps1'
@'
\$ErrorActionPreference = 'Stop'
\$repo = '$GUEST_REPO'
\$artifact = '$GUEST_ARTIFACT_ROOT\\windows-exit-dns-ui'
\$app = '$GUEST_REPO\\windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish\\NostrVpn.Windows.exe'
\$cli = '$GUEST_REPO\\windows\\NostrVpn.Windows\\bin\\Release\\net8.0-windows\\win-x64\\publish\\nvpn.exe'
\$driver = Join-Path \$repo 'scripts\\desktop-mobile-manual-join-windows-ui.ps1'
\$appSha = '$app_sha'
\$appTree = '$app_tree'
\$cases = @(
  @{ Case='automatic'; Mode='automatic'; Provider='cloudflare'; Url=''; Bootstrap=''; Through='' },
  @{ Case='cloudflare'; Mode='encrypted'; Provider='cloudflare'; Url=''; Bootstrap=''; Through='' },
  @{ Case='quad9'; Mode='encrypted'; Provider='quad9'; Url=''; Bootstrap=''; Through='' },
  @{ Case='custom'; Mode='encrypted'; Provider='custom'; Url='https://dns.google/dns-query'; Bootstrap='8.8.8.8,8.8.4.4'; Through='' },
  @{ Case='through-exit'; Mode='through_exit'; Provider='cloudflare'; Url=''; Bootstrap=''; Through='10.99.79.53' }
)
foreach (\$item in \$cases) {
  \$data = Join-Path \$artifact ('data-' + \$item.Case)
  if (Test-Path -LiteralPath \$data) {
    throw ('isolated Windows DNS UI data directory already exists for ' + \$item.Case)
  }
  New-Item -ItemType Directory -Path \$data | Out-Null
  \$marker = Join-Path \$artifact (\$item.Case + '.json')
  \$driverArguments = @{
    Mode = 'DnsPolicy'
    AppExe = \$app
    CliExe = \$cli
    DataDir = \$data
    MarkerPath = \$marker
    Case = \$item.Case
    DnsMode = \$item.Mode
    DnsProvider = \$item.Provider
    DnsCustomUrl = [string]\$item.Url
    DnsBootstrapIps = [string]\$item.Bootstrap
    DnsThroughServers = [string]\$item.Through
    AppGitSha = \$appSha
    AppGitTree = \$appTree
  }
  & \$driver @driverArguments
  if (!\$?) {
    throw ('shipped Windows DNS UI failed for ' + \$item.Case)
  }
}
'@ | Set-Content -Encoding utf8 \$wrapper
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\run-windows-interactive-e2e.ps1 -ScriptPath \$wrapper -TimeoutSeconds 240
if (\$LASTEXITCODE -ne 0) {
  throw ('interactive Windows DNS UI e2e failed with exit code {0}' -f \$LASTEXITCODE)
}
\$expected = @('automatic','cloudflare','quad9','custom','through-exit')
foreach (\$case in \$expected) {
  \$path = Join-Path \$artifact (\$case + '.json')
  if (!(Test-Path -LiteralPath \$path -PathType Leaf)) {
    throw ('Windows DNS UI receipt is missing: ' + \$case)
  }
  \$value = Get-Content -Raw -LiteralPath \$path | ConvertFrom-Json
  if (
    \$value.receiptSchema -ne 1 -or
    \$value.platform -ne 'windows' -or
    \$value.case -ne \$case -or
    \$value.savedViaShippedUi -ne \$true -or
    \$value.uiRestartReadback -ne \$true -or
    \$value.privateStateRead -ne \$false -or
    \$value.appGitSha -ne \$appSha -or
    \$value.appGitTree -ne \$appTree -or
    \$value.appExecutableSha256 -ne \$expectedAppHash -or
    \$value.cliExecutableSha256 -ne \$expectedCliHash
  ) {
    throw ('invalid Windows DNS UI receipt: ' + \$case)
  }
}
\$zip = Join-Path \$artifact 'receipts.zip'
Compress-Archive -Force -Path (
  \$expected | ForEach-Object { Join-Path \$artifact (\$_ + '.json') }
) -DestinationPath \$zip"

rm -rf "$LOCAL_ARTIFACT_DIR"
mkdir -p "$LOCAL_ARTIFACT_DIR"
scp_command
remote_zip="${GUEST_ARTIFACT_ROOT//\\//}/windows-exit-dns-ui/receipts.zip"
"${SCP_CMD[@]}" "$SSH_HOST:$remote_zip" "$LOCAL_ARTIFACT_DIR/receipts.zip"
ditto -x -k "$LOCAL_ARTIFACT_DIR/receipts.zip" "$LOCAL_ARTIFACT_DIR"
rm -f "$LOCAL_ARTIFACT_DIR/receipts.zip"

echo "WINDOWS_VM_EXIT_DNS_UI_E2E_OK"
