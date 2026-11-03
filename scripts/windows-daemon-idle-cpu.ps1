param(
  [Parameter(Mandatory = $true)]
  [string]$Bin,
  [string]$ArtifactRoot,
  [double]$MaxPercent = -1,
  [double]$SampleSeconds = -1,
  [double]$SettleSeconds = -1
)

$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
if (!$ArtifactRoot) { $ArtifactRoot = Join-Path $Root 'artifacts' }
if ($MaxPercent -lt 0) { $MaxPercent = if ($env:NVPN_WINDOWS_DAEMON_IDLE_CPU_MAX_PERCENT) { [double]$env:NVPN_WINDOWS_DAEMON_IDLE_CPU_MAX_PERCENT } else { 2 } }
if ($SampleSeconds -lt 0) { $SampleSeconds = if ($env:NVPN_WINDOWS_DAEMON_IDLE_CPU_SAMPLE_SECONDS) { [double]$env:NVPN_WINDOWS_DAEMON_IDLE_CPU_SAMPLE_SECONDS } else { 60 } }
if ($SettleSeconds -lt 0) { $SettleSeconds = if ($env:NVPN_WINDOWS_DAEMON_IDLE_CPU_SETTLE_SECONDS) { [double]$env:NVPN_WINDOWS_DAEMON_IDLE_CPU_SETTLE_SECONDS } else { 15 } }

$Bin = [IO.Path]::GetFullPath($Bin)
$ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)
$ResultPath = Join-Path $ArtifactRoot 'windows-daemon-idle-cpu.json'
$Fixture = Join-Path $env:TEMP "nvpn-idle-cpu-$PID"
$Config = Join-Path $Fixture 'node-a.toml'
$PeerConfig = Join-Path $Fixture 'node-b.toml'
$daemon = $null

function Get-Npub([string]$Path) {
  $match = Select-String -Path $Path -Pattern '^public_key\s*=\s*"([^"]+)"' | Select-Object -First 1
  if (!$match) { throw "No Nostr public key in $Path" }
  return $match.Matches[0].Groups[1].Value
}

function Get-UsableHostIPv4 {
  $routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
    Where-Object { $_.NextHop -ne '0.0.0.0' } |
    Sort-Object RouteMetric
  foreach ($route in $routes) {
    $address = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue |
      Where-Object {
        $_.AddressState -eq 'Preferred' -and
        $_.IPAddress -notlike '127.*' -and
        $_.IPAddress -notlike '169.254.*'
      } |
      Select-Object -First 1 -ExpandProperty IPAddress
    if ($address) { return $address }
  }
  throw 'No usable non-loopback IPv4 address found for the Windows idle fixture'
}

function Invoke-Nvpn {
  param([string[]]$Arguments)
  & $Bin @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "nvpn $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Find-FixtureDaemon {
  $pidFile = Join-Path $Fixture 'daemon.pid'
  if (!(Test-Path $pidFile)) { return $null }
  try {
    $record = Get-Content $pidFile -Raw | ConvertFrom-Json
    return Get-Process -Id ([int]$record.pid) -ErrorAction Stop
  } catch {
    return $null
  }
}

function Wait-NvpnSeconds([double]$Seconds) {
  $watch = [Diagnostics.Stopwatch]::StartNew()
  while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
    Start-Sleep -Milliseconds ([Math]::Min(250, [Math]::Max(1, [int](($Seconds - $watch.Elapsed.TotalSeconds) * 1000))))
  }
}

$originalProgramData = $env:ProgramData
try {
  if (!(Test-Path $Bin)) { throw "nvpn.exe not found: $Bin" }
  New-Item -ItemType Directory -Force -Path $ArtifactRoot, $Fixture | Out-Null
  # Give this test daemon its own state and instance lock alongside the installed service.
  $env:ProgramData = $Fixture
  Invoke-Nvpn @('init', '--config', $Config, '--force') | Out-Null
  Invoke-Nvpn @('init', '--config', $PeerConfig, '--force') | Out-Null
  $ownNpub = Get-Npub $Config
  $peerNpub = Get-Npub $PeerConfig
  $hostIPv4 = Get-UsableHostIPv4
  Invoke-Nvpn @(
    'set', '--config', $Config,
    '--participant', $ownNpub,
    '--participant', $peerNpub,
    '--network-id', 'windows-idle-cpu',
    '--endpoint', "${hostIPv4}:51891",
    '--listen-port', '51891',
    '--fips-peer-endpoint', "${peerNpub}=${hostIPv4}:51892",
    '--fips-advertise-endpoint', 'true',
    '--fips-nostr-discovery-enabled', 'false',
    '--fips-bootstrap-enabled', 'false'
  ) | Out-Null
  Invoke-Nvpn @(
    'start', '--config', $Config,
    '--iface', 'nvpn-idle-cpu',
    '--daemon', '--connect'
  ) | Out-Null

  $deadline = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $deadline -and !$daemon) {
    Start-Sleep -Milliseconds 250
    $daemon = Find-FixtureDaemon
  }
  if (!$daemon) { throw 'Candidate Windows nvpn daemon did not start' }

  Wait-NvpnSeconds $SettleSeconds
  $daemon.Refresh()
  $startCpu = $daemon.TotalProcessorTime.TotalSeconds
  $watch = [Diagnostics.Stopwatch]::StartNew()
  Wait-NvpnSeconds $SampleSeconds
  $watch.Stop()
  $daemon.Refresh()
  if ($daemon.HasExited) { throw 'Candidate Windows nvpn daemon exited during idle sample' }
  $cpuPercent = [Math]::Max(0.0, $daemon.TotalProcessorTime.TotalSeconds - $startCpu) * 100 / [Math]::Max(0.001, $watch.Elapsed.TotalSeconds)
  $ok = $cpuPercent -le $MaxPercent
  [pscustomobject]@{
    ok = $ok
    mode = 'windows-active-daemon'
    label = 'Windows nvpn active daemon'
    pids = @($daemon.Id)
    cpuPercent = $cpuPercent
    maxPercent = $MaxPercent
    sampleSeconds = $SampleSeconds
    settleSeconds = $SettleSeconds
    elapsedSeconds = $watch.Elapsed.TotalSeconds
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
  } | ConvertTo-Json -Depth 4 | Out-File -Encoding utf8 $ResultPath
  if (!$ok) { throw ("Windows daemon idle CPU {0:N3}% > {1:N3}%" -f $cpuPercent, $MaxPercent) }
  Write-Host ("Windows daemon idle CPU ok: {0:N3}% <= {1:N3}%" -f $cpuPercent, $MaxPercent)
  Write-Host "Result: $ResultPath"
} finally {
  if ($daemon -and !$daemon.HasExited) { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue }
  if ((Test-Path $Bin) -and (Test-Path $Config)) {
    & $Bin stop --config $Config --force 2>$null | Out-Null
  }
  $env:ProgramData = $originalProgramData
  $daemonLog = Join-Path $Fixture 'daemon.log'
  if (Test-Path -LiteralPath $daemonLog -PathType Leaf) {
    Copy-Item -LiteralPath $daemonLog -Destination (Join-Path $ArtifactRoot 'daemon.log')
  }
  Remove-Item -Recurse -Force $Fixture -ErrorAction SilentlyContinue
}
