param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [string]$ArtifactRoot = "C:\Mac\Home\src\nostr-vpn\artifacts",
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$FixtureDir = Join-Path $ArtifactRoot "update-fixtures\windows"
$DownloadDir = Join-Path $ArtifactRoot "update-downloads\windows"
$ResultPath = Join-Path $ArtifactRoot "windows-update-e2e.json"
$Tag = if ($env:NVPN_UPDATE_E2E_TAG) { $env:NVPN_UPDATE_E2E_TAG } else { "v99.0.0" }
$Arch = $env:PROCESSOR_ARCHITECTURE
$AssetName = if ($Arch -match "ARM64") {
  "nostr-vpn-$Tag-windows-arm64-setup.exe"
} else {
  "nostr-vpn-$Tag-windows-x64-setup.exe"
}
$ManifestPath = Join-Path $FixtureDir "release.json"
$AssetPath = Join-Path $FixtureDir $AssetName
$AppExe = Join-Path $Root "windows\NostrVpn.Windows\bin\$Configuration\net8.0-windows\NostrVpn.Windows.exe"

New-Item -ItemType Directory -Force -Path $FixtureDir, $DownloadDir, $ArtifactRoot | Out-Null
if (!$env:CARGO_TARGET_DIR) {
  $env:CARGO_TARGET_DIR = Join-Path $env:LOCALAPPDATA "nostr-vpn-cargo-target"
}
Set-Content -Path $AssetPath -Value "nostr vpn windows update fixture" -Encoding ascii
# The updater's JSON parser rejects a UTF-8 BOM, so write the manifest without one.
$ManifestJson = @{
  tag = $Tag
  assets = @(@{ name = $AssetName; path = $AssetName })
} | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($ManifestPath, $ManifestJson, [System.Text.UTF8Encoding]::new($false))

if (!$SkipBuild) {
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "scripts\windows-build.ps1") -Configuration $Configuration
  if ($LASTEXITCODE -ne 0) {
    throw "windows-build.ps1 failed with exit code $LASTEXITCODE"
  }
}
if (!(Test-Path $AppExe)) {
  throw "Built Windows app not found: $AppExe"
}

function Invoke-UpdateE2E {
  param([string[]]$AppArgs)
  Get-Process -Name NostrVpn.Windows -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Remove-Item -Force $ResultPath -ErrorAction SilentlyContinue
  $process = Start-Process -FilePath $AppExe `
    -ArgumentList $AppArgs `
    -PassThru `
    -Wait
  return $process.ExitCode
}

function Read-UpdateE2EResult {
  return Get-Content $ResultPath -Raw | ConvertFrom-Json
}

$env:NVPN_UPDATE_E2E_RESULT_PATH = $ResultPath
$env:NVPN_UPDATE_DOWNLOAD_DIR = $DownloadDir
$env:NVPN_UPDATE_SKIP_OPEN = "1"

# Phase A (offline): the NVPN_UPDATE_MANIFEST_URL override is tooling-only and
# its result stays unverified, so a check must succeed but an install attempt
# must be refused.
$env:NVPN_UPDATE_MANIFEST_URL = ([Uri](Resolve-Path $ManifestPath).Path).AbsoluteUri
$env:NVPN_UPDATE_E2E_CURRENT_VERSION = "0.0.0"

$exitCode = Invoke-UpdateE2E @("--nvpn-e2e-update-check")
$result = Read-UpdateE2EResult
if ($exitCode -ne 0 -or !$result.ok) {
  throw "Windows update e2e check failed (exit $exitCode): $($result.error)"
}
if (!$result.available) {
  throw "Windows update was not detected as available"
}
if (!$result.assetName -or $result.assetName -notmatch "windows-(x64|arm64)-setup\.exe$") {
  throw "Unexpected Windows asset: $($result.assetName)"
}
Write-Host "Phase A check result: $($result | ConvertTo-Json -Depth 5 -Compress)"

$exitCode = Invoke-UpdateE2E @("--nvpn-e2e-update-check", "--nvpn-e2e-install-update")
if ($exitCode -eq 0) {
  throw "Unverified fixture update install was not refused"
}
$result = Read-UpdateE2EResult
if ($result.ok) {
  throw "Unverified fixture update install was not refused"
}
Write-Host "Phase A install refusal: $($result.error)"

# Phase B (online): without the override the signed hashtree path over FIPS
# pubsub is canonical and must resolve without error, whether an update is
# available or the app is up to date.
Remove-Item Env:\NVPN_UPDATE_MANIFEST_URL -ErrorAction SilentlyContinue
Remove-Item Env:\NVPN_UPDATE_E2E_CURRENT_VERSION -ErrorAction SilentlyContinue

$exitCode = Invoke-UpdateE2E @("--nvpn-e2e-update-check")
$result = Read-UpdateE2EResult
if ($exitCode -ne 0 -or !$result.ok) {
  throw "Windows secure update check failed (exit $exitCode): $($result.error)"
}
Write-Host "Phase B check result: $($result | ConvertTo-Json -Depth 5 -Compress)"

Write-Host "WINDOWS_UPDATE_E2E_OK"
Write-Host "Result: $ResultPath"
