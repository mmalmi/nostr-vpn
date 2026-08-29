param(
  [Parameter(Mandatory = $true)]
  [ValidateSet(
    "Prepare",
    "Reset",
    "Bootstrap",
    "InstallService",
    "CreateAdmin",
    "AdminAdd",
    "ManualJoin",
    "Verify",
    "ReadMarker",
    "ReadReceipt",
    "ReadDaemonLog",
    "Stop",
    "NowMs",
    "Cleanup"
  )]
  [string]$Mode,
  [Parameter(Mandatory = $true)]
  [string]$RepoRoot,
  [Parameter(Mandatory = $true)]
  [string]$ArtifactRoot,
  [Parameter(Mandatory = $true)]
  [string]$AppExe,
  [string]$FipsRepo = "",
  [string]$ExpectedAppGitSha = "",
  [string]$ExpectedAppGitTree = "",
  [string]$ExpectedFipsGitSha = "",
  [string]$ExpectedFipsGitTree = "",
  [string]$ExpectedFipsVersion = "",
  [string]$NetworkName = "Release Windows admin",
  [string]$AdminNpub = "",
  [string]$NetworkId = "",
  [string]$ParticipantNpub = "",
  [string]$ParticipantAlias = "Release Pixel"
)

$ErrorActionPreference = "Stop"
$UiDriver = Join-Path $RepoRoot "scripts\desktop-mobile-manual-join-windows-ui.ps1"
$InteractiveRunner = Join-Path $RepoRoot "scripts\run-windows-interactive-e2e.ps1"
$MarkerPath = Join-Path $ArtifactRoot "action.json"
$StopPath = Join-Path $ArtifactRoot "stop"
$ReceiptPath = Join-Path $ArtifactRoot "windows-release-artifact.json"
$WrapperPath = Join-Path $ArtifactRoot "interactive-action.ps1"
$CliExe = Join-Path (Split-Path -Parent $AppExe) "nvpn.exe"
$ServiceName = "NvpnService"
$AppCoreDll = Join-Path (Split-Path -Parent $AppExe) "nostr_vpn_app_core.dll"
$WintunDll = Join-Path (Split-Path -Parent $AppExe) "binaries\wintun.dll"

function Assert-GitHash {
  param([string]$Value, [string]$Label)
  if ($Value -notmatch '^[0-9a-f]{40}$') {
    throw "$Label must be an exact 40-character Git SHA"
  }
}

function Get-Sha256 {
  param([string]$Path)
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Read-TomlVersion {
  param([string]$Path, [string]$Section)
  $InSection = $false
  foreach ($Line in Get-Content -LiteralPath $Path) {
    $Trimmed = $Line.Trim()
    if ($Trimmed -eq "[$Section]") {
      $InSection = $true
      continue
    }
    if ($InSection -and $Trimmed.StartsWith("[")) {
      break
    }
    if ($InSection -and $Trimmed -match '^version\s*=\s*"([^"]+)"') {
      return $Matches[1]
    }
  }
  throw "could not read $Section version from $Path"
}

function Write-JsonAtomically {
  param([object]$Value, [string]$Path)
  $Directory = Split-Path -Parent $Path
  New-Item -ItemType Directory -Force -Path $Directory | Out-Null
  $Temporary = Join-Path $Directory (
    ".{0}.{1}.{2}.tmp" -f (Split-Path -Leaf $Path), $PID, [Guid]::NewGuid().ToString("N")
  )
  try {
    $Value | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 -Path $Temporary
    Move-Item -Force -Path $Temporary -Destination $Path
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $Temporary
  }
}

function Quote-PowerShellLiteral {
  param([string]$Value)
  return "'" + $Value.Replace("'", "''") + "'"
}

function Resolve-InteractiveProfile {
  $InteractiveUser = (Get-CimInstance Win32_ComputerSystem).UserName
  if ([string]::IsNullOrWhiteSpace($InteractiveUser)) {
    throw "no interactively logged-in Windows user is available"
  }
  $Account = New-Object System.Security.Principal.NTAccount($InteractiveUser)
  $Sid = $Account.Translate([System.Security.Principal.SecurityIdentifier]).Value
  $Profile = Get-CimInstance Win32_UserProfile |
    Where-Object { $_.SID -eq $Sid } |
    Select-Object -First 1
  if (!$Profile -or [string]::IsNullOrWhiteSpace($Profile.LocalPath)) {
    throw "could not resolve the interactive Windows user profile"
  }
  return $Profile.LocalPath
}

function Resolve-CanonicalConfig {
  $Profile = Resolve-InteractiveProfile
  return Join-Path $Profile "AppData\Roaming\Nostr VPN\config.toml"
}

function Normalize-ComparableWindowsPath {
  param([string]$Path)
  $Value = $Path.Trim()
  if ($Value.StartsWith('\\?\', [System.StringComparison]::Ordinal)) {
    $Value = $Value.Substring(4)
  }
  return [IO.Path]::GetFullPath($Value).TrimEnd('\')
}

function Assert-SourceAndArtifacts {
  Assert-GitHash $ExpectedAppGitSha "ExpectedAppGitSha"
  Assert-GitHash $ExpectedAppGitTree "ExpectedAppGitTree"
  Assert-GitHash $ExpectedFipsGitSha "ExpectedFipsGitSha"
  Assert-GitHash $ExpectedFipsGitTree "ExpectedFipsGitTree"
  if (!(Test-Path -LiteralPath $AppExe -PathType Leaf)) {
    throw "Windows Release app is missing: $AppExe"
  }
  if (!(Test-Path -LiteralPath $CliExe -PathType Leaf)) {
    throw "Windows Release app has no adjacent nvpn.exe: $CliExe"
  }
  if (!(Test-Path -LiteralPath $AppCoreDll -PathType Leaf)) {
    throw "Windows Release app has no adjacent app-core DLL: $AppCoreDll"
  }
  if (!(Test-Path -LiteralPath $WintunDll -PathType Leaf)) {
    throw "Windows Release app has no adjacent Wintun DLL: $WintunDll"
  }
  if (!(Test-Path -LiteralPath $FipsRepo -PathType Container)) {
    throw "exact FIPS checkout is missing: $FipsRepo"
  }
  $AppHead = (& git -C $RepoRoot rev-parse HEAD).Trim()
  $AppTree = (& git -C $RepoRoot rev-parse 'HEAD^{tree}').Trim()
  $AppStatus = (& git -C $RepoRoot status --porcelain --untracked-files=all | Out-String).Trim()
  $FipsHead = (& git -C $FipsRepo rev-parse HEAD).Trim()
  $FipsTree = (& git -C $FipsRepo rev-parse 'HEAD^{tree}').Trim()
  $FipsStatus = (& git -C $FipsRepo status --porcelain --untracked-files=all | Out-String).Trim()
  if (
    $AppHead -ne $ExpectedAppGitSha -or
    $AppTree -ne $ExpectedAppGitTree -or
    $AppStatus
  ) {
    throw "Windows guest app source is not the clean exact candidate"
  }
  if (
    $FipsHead -ne $ExpectedFipsGitSha -or
    $FipsTree -ne $ExpectedFipsGitTree -or
    $FipsStatus
  ) {
    throw "Windows guest FIPS source is not the clean exact candidate"
  }
  $ShortVersion = (& $CliExe --version | Out-String).Trim()
  $VerboseVersion = (& $CliExe version --verbose | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) {
    throw "Windows candidate nvpn version command failed"
  }
  if ($VerboseVersion -notmatch [regex]::Escape("(rev $($ExpectedFipsGitSha.Substring(0, 10)))")) {
    throw "Windows nvpn binary does not contain the expected FIPS revision"
  }
  $AppVersion = $ShortVersion -replace '^nvpn\s+', ''
  if ($AppVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$') {
    throw "Windows nvpn binary did not report a release version"
  }
  if ($ExpectedFipsVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$') {
    throw "ExpectedFipsVersion is invalid"
  }
  $WorkspaceVersion = Read-TomlVersion (Join-Path $RepoRoot "Cargo.toml") "workspace.package"
  $FipsVersion = Read-TomlVersion (
    Join-Path $FipsRepo "crates\fips-core\Cargo.toml"
  ) "package"
  if ($AppVersion -ne $WorkspaceVersion) {
    throw "Windows nvpn binary version differs from the exact app source"
  }
  if ($FipsVersion -ne $ExpectedFipsVersion) {
    throw "Windows FIPS checkout version differs from the expected release dependency"
  }
  return [ordered]@{
    schema = 1
    platform = "windows"
    configuration = "Release"
    builtOnWindowsVm = $true
    appGitSha = $AppHead
    appGitTree = $AppTree
    appVersion = $AppVersion
    fipsGitSha = $FipsHead
    fipsGitTree = $FipsTree
    fipsVersion = $ExpectedFipsVersion
    artifacts = [ordered]@{
      app = [ordered]@{
        file = (Split-Path -Leaf $AppExe)
        sha256 = Get-Sha256 $AppExe
        size = (Get-Item -LiteralPath $AppExe).Length
      }
      appCore = [ordered]@{
        file = (Split-Path -Leaf $AppCoreDll)
        sha256 = Get-Sha256 $AppCoreDll
        size = (Get-Item -LiteralPath $AppCoreDll).Length
      }
      cli = [ordered]@{
        file = (Split-Path -Leaf $CliExe)
        sha256 = Get-Sha256 $CliExe
        size = (Get-Item -LiteralPath $CliExe).Length
        shortVersion = $ShortVersion
        verboseVersion = $VerboseVersion
      }
      wintun = [ordered]@{
        file = "binaries\wintun.dll"
        sha256 = Get-Sha256 $WintunDll
        size = (Get-Item -LiteralPath $WintunDll).Length
      }
    }
  }
}

function Assert-PreparedReceipt {
  if (!(Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) {
    throw "Windows Release artifact receipt has not been prepared"
  }
  $Expected = Assert-SourceAndArtifacts
  $Receipt = Get-Content -Raw -LiteralPath $ReceiptPath | ConvertFrom-Json
  foreach ($Name in @(
    "platform",
    "configuration",
    "appGitSha",
    "appGitTree",
    "appVersion",
    "fipsGitSha",
    "fipsGitTree",
    "fipsVersion"
  )) {
    if ($Receipt.$Name -ne $Expected.$Name) {
      throw "Windows Release artifact receipt changed at $Name"
    }
  }
  foreach ($Name in @("app", "appCore", "cli", "wintun")) {
    if (
      $Receipt.artifacts.$Name.sha256 -ne $Expected.artifacts.$Name.sha256 -or
      [long]$Receipt.artifacts.$Name.size -ne [long]$Expected.artifacts.$Name.size
    ) {
      throw "Windows Release $Name artifact changed after preparation"
    }
  }
}

function Invoke-InteractiveAction {
  param([string]$Action)
  Assert-PreparedReceipt
  Remove-Item -Force -ErrorAction SilentlyContinue $MarkerPath, $StopPath
  $Arguments = @(
    "-Mode", (Quote-PowerShellLiteral $Action),
    "-AppExe", (Quote-PowerShellLiteral $AppExe),
    "-MarkerPath", (Quote-PowerShellLiteral $MarkerPath),
    "-StopPath", (Quote-PowerShellLiteral $StopPath),
    "-NetworkName", (Quote-PowerShellLiteral $NetworkName),
    "-AdminNpub", (Quote-PowerShellLiteral $AdminNpub),
    "-NetworkId", (Quote-PowerShellLiteral $NetworkId),
    "-ParticipantNpub", (Quote-PowerShellLiteral $ParticipantNpub),
    "-ParticipantAlias", (Quote-PowerShellLiteral $ParticipantAlias)
  )
  $Invocation = (
    "& {0} {1}`nif (`$LASTEXITCODE -is [int] -and `$LASTEXITCODE -ne 0) " +
    "{{ exit `$LASTEXITCODE }}"
  ) -f (Quote-PowerShellLiteral $UiDriver), ($Arguments -join " ")
  Set-Content -Encoding utf8 -Path $WrapperPath -Value $Invocation
  & $InteractiveRunner -ScriptPath $WrapperPath -TimeoutSeconds 150
  if ($LASTEXITCODE -is [int] -and $LASTEXITCODE -ne 0) {
    throw "Windows interactive $Action action failed"
  }
}

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null

switch ($Mode) {
  "Prepare" {
    if ($AppExe -notmatch '\\Release\\') {
      throw "Windows desktop/mobile join gate requires a Release app path"
    }
    $Receipt = Assert-SourceAndArtifacts
    Write-JsonAtomically $Receipt $ReceiptPath
    Write-Output "WINDOWS_RELEASE_MOBILE_JOIN_ARTIFACT_READY"
  }
  "ReadReceipt" {
    Assert-PreparedReceipt
    Get-Content -Raw -LiteralPath $ReceiptPath
  }
  "ReadDaemonLog" {
    $Config = Resolve-CanonicalConfig
    $Log = Join-Path (Split-Path -Parent $Config) "daemon.log"
    if (Test-Path -LiteralPath $Log -PathType Leaf) {
      Get-Content -LiteralPath $Log -Tail 300
    }
  }
  "ReadMarker" {
    if (!(Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
      throw "Windows desktop/mobile join marker is not ready"
    }
    Get-Content -Raw -LiteralPath $MarkerPath
  }
  "Stop" {
    Set-Content -Encoding ascii -Path $StopPath -Value "stop"
  }
  "NowMs" {
    Write-Output ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
  }
  "Cleanup" {
    $CandidatePaths = @($AppExe, $CliExe)
    Get-Process -ErrorAction SilentlyContinue |
      Where-Object {
        try { $CandidatePaths -icontains $_.Path } catch { $false }
      } |
      Stop-Process -Force -ErrorAction SilentlyContinue
    $Service = Get-CimInstance Win32_Service `
      -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($Service) {
      $Config = Resolve-CanonicalConfig
      $Command = [regex]::Match(
        [string]$Service.PathName,
        '^"(?<binary>[^"]+)"(?<arguments> .*)$'
      )
      $ConfigArgument = [regex]::Match(
        $Command.Groups['arguments'].Value,
        '^ daemon --service --config "(?<config>[^"]+)" --iface "(?<iface>[^"]+)" --mesh-refresh-interval-secs (?<refresh>[1-9][0-9]*)\s*$'
      )
      if (
        !$Command.Success -or
        !$ConfigArgument.Success -or
        ![string]::Equals(
          (Normalize-ComparableWindowsPath $ConfigArgument.Groups['config'].Value),
          (Normalize-ComparableWindowsPath $Config),
          [System.StringComparison]::OrdinalIgnoreCase
        )
      ) {
        throw "refusing to remove a Windows service outside this candidate profile"
      }
      $ServiceExecutable = $Command.Groups['binary'].Value
      if (
        !(Test-Path -LiteralPath $ServiceExecutable -PathType Leaf) -or
        (Get-Sha256 $ServiceExecutable) -ne (Get-Sha256 $CliExe)
      ) {
        throw "refusing to remove a Windows service outside this candidate artifact"
      }
      & $CliExe service uninstall --config $Config
      if ($LASTEXITCODE -ne 0) {
        throw "exact Windows candidate service cleanup failed"
      }
    }
    $Deadline = (Get-Date).AddSeconds(15)
    do {
      $RemainingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
      $RemainingProcesses = @(
        Get-Process -ErrorAction SilentlyContinue |
          Where-Object {
            try { $CandidatePaths -icontains $_.Path } catch { $false }
          }
      )
      if (!$RemainingService -and $RemainingProcesses.Count -eq 0) { break }
      Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $Deadline)
    if ($RemainingService -or $RemainingProcesses.Count -ne 0) {
      throw "Windows candidate cleanup left a service or process behind"
    }
    Remove-Item -Force -ErrorAction SilentlyContinue $StopPath, $WrapperPath
    Write-Output "WINDOWS_RELEASE_MOBILE_JOIN_CLEAN"
  }
  "InstallService" {
    Assert-PreparedReceipt
    $Config = Resolve-CanonicalConfig
    if (!(Test-Path -LiteralPath $Config -PathType Leaf)) {
      throw "canonical Windows profile was not bootstrapped before service installation"
    }
    & $CliExe service install --force --config $Config
    if ($LASTEXITCODE -ne 0) {
      throw "exact Windows candidate service installation failed"
    }
    $Service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($Service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
      $Service.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(15)
      )
    }
    Write-Output "WINDOWS_RELEASE_MOBILE_JOIN_SERVICE_READY"
  }
  "Reset" {
    Assert-PreparedReceipt
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Invoke-InteractiveAction "Reset"
  }
  "Bootstrap" {
    Invoke-InteractiveAction "Bootstrap"
  }
  "CreateAdmin" {
    Invoke-InteractiveAction "CreateAdmin"
  }
  "AdminAdd" {
    Invoke-InteractiveAction "AdminAdd"
  }
  "ManualJoin" {
    Invoke-InteractiveAction "ManualJoin"
  }
  "Verify" {
    Invoke-InteractiveAction "Verify"
  }
}
