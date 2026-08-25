param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [switch]$Run,
  [switch]$Publish,
  [switch]$Installer,
  [switch]$DaemonOnly,
  [string]$Tag,
  [string]$OutputDir,
  [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Project = Join-Path $Root "windows\NostrVpn.Windows\NostrVpn.Windows.csproj"
$CargoTargetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $Root "target" }
$CargoProfile = if ($Configuration -eq "Release") { "release" } else { "debug" }
$WorkspaceCargoToml = Join-Path $Root "Cargo.toml"
$CargoLock = Join-Path $Root "Cargo.lock"
$CargoConfigArgs = @()
$CargoLockArgs = @("--locked")
$LockSnapshot = $null
$ManifestSnapshot = $null

Set-Location $Root

$LlvmBin = if ($env:NVPN_WINDOWS_LLVM_BIN) { $env:NVPN_WINDOWS_LLVM_BIN } else { "C:\Program Files\LLVM\bin" }
if (Test-Path (Join-Path $LlvmBin "clang.exe")) {
  $env:PATH = "$LlvmBin;$env:PATH"
}

function Invoke-Checked {
  param(
    [string]$FilePath,
    [string[]]$Arguments
  )
  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath failed with exit code $LASTEXITCODE"
  }
}

function Enable-DeterministicBuildEnv {
  if (!$env:SOURCE_DATE_EPOCH) {
    $Epoch = (& git -C $Root log -1 --format=%ct HEAD 2>$null)
    if (!$Epoch) {
      $Epoch = "0"
    }
    $env:SOURCE_DATE_EPOCH = $Epoch
  }
  if ($env:SOURCE_DATE_EPOCH -notmatch '^\d+$') {
    throw "SOURCE_DATE_EPOCH must be a Unix timestamp, got: $env:SOURCE_DATE_EPOCH"
  }
  if (!$env:CARGO_INCREMENTAL) {
    $env:CARGO_INCREMENTAL = "0"
  }
  if (!$env:ZERO_AR_DATE) {
    $env:ZERO_AR_DATE = "1"
  }
}

function Get-WorkspaceVersion {
  $Text = Get-Content -Raw -Path $WorkspaceCargoToml
  $Match = [regex]::Match($Text, '(?ms)^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"')
  if (!$Match.Success) {
    throw "Could not read workspace version from $WorkspaceCargoToml"
  }
  return $Match.Groups[1].Value
}

function Resolve-InnoSetupCompiler {
  $Command = Get-Command iscc -ErrorAction SilentlyContinue
  if ($Command) {
    return $Command.Source
  }

  $Candidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
  )
  foreach ($Candidate in $Candidates) {
    if ($Candidate -and (Test-Path $Candidate)) {
      return $Candidate
    }
  }

  throw "Inno Setup compiler not found. Install JRSoftware.InnoSetup or put ISCC.exe on PATH."
}

function Resolve-OutputPath {
  param([string]$Path)
  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }
  return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Copy-RequiredFile {
  param(
    [string]$Source,
    [string]$Destination,
    [string]$Label
  )

  if (!(Test-Path $Source)) {
    throw "Missing ${Label}: $Source"
  }

  $DestinationParent = Split-Path -Parent $Destination
  New-Item -ItemType Directory -Force -Path $DestinationParent | Out-Null
  if ([System.IO.Path]::GetFullPath($Source) -ine [System.IO.Path]::GetFullPath($Destination)) {
    Copy-Item -Force $Source $Destination
  }
}

function Assert-BundledWindowsHelpers {
  param([string]$OutputDir)

  $WintunDll = Join-Path $OutputDir "binaries\wintun.dll"
  if (!(Test-Path $WintunDll)) {
    throw "Published Windows app is missing bundled helper: $WintunDll"
  }
}

function Test-FilesDiffer {
  param(
    [string]$Left,
    [string]$Right
  )
  if (!(Test-Path $Left) -or !(Test-Path $Right)) {
    return $true
  }
  return (Get-FileHash -Algorithm SHA256 $Left).Hash -ne (Get-FileHash -Algorithm SHA256 $Right).Hash
}

function Prepare-CargoLockRestore {
  if (!$script:LockSnapshot) {
    $script:LockSnapshot = [System.IO.Path]::GetTempFileName()
    Copy-Item -Force $CargoLock $script:LockSnapshot
  }
  if (!$script:ManifestSnapshot) {
    $script:ManifestSnapshot = [System.IO.Path]::GetTempFileName()
    Copy-Item -Force $WorkspaceCargoToml $script:ManifestSnapshot
  }
}

function Restore-CargoLock {
  if (!$script:LockSnapshot -or !(Test-Path $script:LockSnapshot)) {
    return
  }
  if (Test-FilesDiffer $script:LockSnapshot $CargoLock) {
    Copy-Item -Force $script:LockSnapshot $CargoLock
    Write-Host "restored Cargo.lock after local-FIPS cargo run"
  }
  Remove-Item -Force $script:LockSnapshot -ErrorAction SilentlyContinue
  $script:LockSnapshot = $null

  if ($script:ManifestSnapshot -and (Test-Path $script:ManifestSnapshot)) {
    if (Test-FilesDiffer $script:ManifestSnapshot $WorkspaceCargoToml) {
      Copy-Item -Force $script:ManifestSnapshot $WorkspaceCargoToml
      Write-Host "restored Cargo.toml after local-FIPS cargo run"
    }
    Remove-Item -Force $script:ManifestSnapshot -ErrorAction SilentlyContinue
    $script:ManifestSnapshot = $null
  }
}

function Convert-ToCargoPath {
  param([string]$Path)
  return ((Resolve-Path $Path).Path -replace '\\', '/')
}

function Prepare-LocalFipsPatch {
  if (!$env:NVPN_FIPS_REPO_PATH) {
    return
  }

  $FipsRoot = (Resolve-Path $env:NVPN_FIPS_REPO_PATH).Path
  Prepare-CargoLockRestore
  $ManifestText = Get-Content -Raw -Path $WorkspaceCargoToml
  $FipsCrates = @(
    @{ Alias = "fips-core"; Package = "nvpn-fips-core" },
    @{ Alias = "fips-endpoint"; Package = "nvpn-fips-endpoint" },
    @{ Alias = "fips-identity"; Package = "nvpn-fips-identity" }
  )
  foreach ($Crate in $FipsCrates) {
    $CrateName = $Crate.Alias
    $PackageName = $Crate.Package
    $CrateDir = Join-Path $FipsRoot "crates\$CrateName"
    if (!(Test-Path (Join-Path $CrateDir "Cargo.toml"))) {
      throw "NVPN_FIPS_REPO_PATH must point at a fips checkout with ${CrateName}: $CrateDir"
    }
    $CargoPath = Convert-ToCargoPath $CrateDir
    $script:CargoConfigArgs += @("--config", "patch.crates-io.$PackageName.path='$CargoPath'")
    $EscapedName = [regex]::Escape($CrateName)
    $Pattern = "(?m)($EscapedName\s*=\s*\{[^\r\n}]*\bpath\s*=\s*)`"[^`"]*`""
    $ManifestText = [regex]::Replace($ManifestText, $Pattern, {
      param($Match)
      $Match.Groups[1].Value + '"' + $CargoPath + '"'
    })
  }
  [System.IO.File]::WriteAllText(
    $WorkspaceCargoToml,
    $ManifestText,
    [System.Text.UTF8Encoding]::new($false)
  )

  $script:CargoLockArgs = @()
  Write-Host "using local FIPS crates from $FipsRoot"
}

try {
  Enable-DeterministicBuildEnv
  Prepare-LocalFipsPatch

  $CargoArgs = @()
  $CargoArgs += $CargoConfigArgs
  $CargoArgs += @("build")
  $CargoArgs += $CargoLockArgs
  if ($DaemonOnly) {
    $CargoArgs += @("-p", "nvpn")
  } else {
    $CargoArgs += @("-p", "nostr-vpn-app-core", "-p", "nvpn")
  }
  if ($Configuration -eq "Release") {
    $CargoArgs += "--release"
  }
  Invoke-Checked cargo $CargoArgs

  if ($DaemonOnly) {
    return
  }

  $CargoOutputDir = Join-Path $CargoTargetRoot $CargoProfile
  $AppCargoDir = $CargoOutputDir
  New-Item -ItemType Directory -Force -Path $AppCargoDir | Out-Null
  foreach ($FileName in @("nostr_vpn_app_core.dll", "nvpn.exe")) {
    $Source = Join-Path $CargoOutputDir $FileName
    $Destination = Join-Path $AppCargoDir $FileName
    Copy-RequiredFile $Source $Destination $FileName
  }
  $AppBinariesDir = Join-Path $AppCargoDir "binaries"
  Copy-RequiredFile (Join-Path $CargoOutputDir "wintun.dll") (Join-Path $AppBinariesDir "wintun.dll") "wintun.dll"

  if ($Publish -or $Installer) {
    $SelfContained = if ($Installer) { "true" } else { "false" }
    Invoke-Checked dotnet @("publish", $Project, "-c", $Configuration, "-r", $Runtime, "--self-contained", $SelfContained, "-p:Deterministic=true", "-p:ContinuousIntegrationBuild=true", "-p:NvpnCargoArtifactsDir=$AppCargoDir")
    $DotnetOutputDir = Join-Path $Root "windows\NostrVpn.Windows\bin\$Configuration\net8.0-windows\$Runtime\publish"
  } else {
    Invoke-Checked dotnet @("build", $Project, "-c", $Configuration, "-p:Deterministic=true", "-p:ContinuousIntegrationBuild=true", "-p:NvpnCargoArtifactsDir=$AppCargoDir")
    $DotnetOutputDir = Join-Path $Root "windows\NostrVpn.Windows\bin\$Configuration\net8.0-windows"
  }
  Assert-BundledWindowsHelpers $DotnetOutputDir

  if ($Installer) {
    if ($Runtime -ne "win-x64") {
      throw "The installer script currently supports win-x64 only, got $Runtime"
    }

    $VersionTag = if ($Tag) { $Tag } else { "v$(Get-WorkspaceVersion)" }
    if (!$VersionTag.StartsWith("v")) {
      $VersionTag = "v$VersionTag"
    }
    # The immutable release tag may carry corrected-build metadata, while the
    # Windows installer remains on the shared product/marketing version.
    $Version = ($VersionTag.TrimStart("v") -split '\+', 2)[0]
    $InstallerOutputDir = if ($OutputDir) { Resolve-OutputPath $OutputDir } else { Join-Path $Root "dist" }
    New-Item -ItemType Directory -Force -Path $InstallerOutputDir | Out-Null

    $PublishDir = $DotnetOutputDir
    if (!(Test-Path (Join-Path $PublishDir "NostrVpn.Windows.exe"))) {
      throw "Published Windows app not found in $PublishDir"
    }

    $env:NVPN_RELEASE_VERSION = $Version
    $env:NVPN_PROJECT_ROOT = $Root
    $env:NVPN_WINDOWS_PUBLISH_DIR = $PublishDir
    $env:NVPN_WINDOWS_INSTALLER_OUTPUT_DIR = $InstallerOutputDir
    $env:NVPN_WINDOWS_INSTALLER_BASENAME = "nostr-vpn-$VersionTag-windows-x64-setup"
    $InnoSetupCompiler = Resolve-InnoSetupCompiler
    Invoke-Checked $InnoSetupCompiler @((Join-Path $Root "scripts\windows-installer.iss"))

    $InstallerPath = Join-Path $InstallerOutputDir "$($env:NVPN_WINDOWS_INSTALLER_BASENAME).exe"
    if (!(Test-Path $InstallerPath)) {
      throw "Expected Windows installer was not produced: $InstallerPath"
    }
  }

  if ($Run) {
    $exe = Join-Path $Root "windows\NostrVpn.Windows\bin\$Configuration\net8.0-windows\NostrVpn.Windows.exe"
    if (!(Test-Path $exe)) {
      throw "Built Windows app not found: $exe"
    }
    & $exe
  }
} finally {
  Restore-CargoLock
}
