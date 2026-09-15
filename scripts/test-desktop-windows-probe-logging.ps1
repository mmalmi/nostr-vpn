param([string]$HelperRoot = $PSScriptRoot)

$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) (
  'nvpn-probe-logging-' + [Guid]::NewGuid().ToString('N')
)
$entry = Join-Path $HelperRoot 'desktop-windows-underlay-change-e2e.ps1'

try {
  foreach ($action in @('Probe', 'WireGuardProbe')) {
    $state = Join-Path $root $action
    [IO.Directory]::CreateDirectory($state) | Out-Null
    $logName = if ($action -eq 'Probe') { 'payload.log' } else { 'wireguard-payload.log' }
    $log = Join-Path $state $logName
    $stderr = Join-Path $state 'stderr.log'
    $command = "& '$($entry.Replace("'", "''"))' -Action $action " +
      "-Binary unused -Config unused -StateDir '$($state.Replace("'", "''"))' " +
      '-PeerTunnelIp 127.0.0.1 -WireGuardServerIp 127.0.0.1'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $process = $null
    $reader = $null
    try {
      $process = Start-Process powershell.exe -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) `
        -RedirectStandardError $stderr `
        -RedirectStandardOutput (Join-Path $state 'stdout.log')
      $timer = [Diagnostics.Stopwatch]::StartNew()
      while (!(Test-Path $log) -and !$process.HasExited -and $timer.ElapsedMilliseconds -lt 10000) {
        Start-Sleep -Milliseconds 25
      }
      if (!(Test-Path $log)) { throw "$action produced no payload receipts: $([IO.File]::ReadAllText($stderr))" }
      # Get-Content uses a shared read handle. Keep the same sharing conditions
      # alive across several production probe writes to make the race deterministic.
      $reader = [IO.File]::Open($log, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      $before = [IO.File]::ReadAllLines($log).Count
      $timer.Restart()
      $after = $before
      while ($after -lt ($before + 5) -and !$process.HasExited -and $timer.ElapsedMilliseconds -lt 3000) {
        Start-Sleep -Milliseconds 25
        $after = [IO.File]::ReadAllLines($log).Count
      }
      if ($process.HasExited -or $after -lt ($before + 5)) {
        $errorText = [IO.File]::ReadAllText($stderr)
        throw "$action stopped recording while its log was read: $errorText"
      }
      if (@([IO.File]::ReadAllLines($log) | Where-Object { $_ -notmatch '^OK [0-9]+$' }).Count) {
        throw "$action did not produce complete successful loopback receipts"
      }
    } finally {
      if ($reader) { $reader.Dispose() }
      [IO.File]::WriteAllText((Join-Path $state 'stop-probe'), 'stop')
      if ($process -and !$process.WaitForExit(3000)) { Stop-Process -Id $process.Id -Force }
    }
  }
  Write-Output 'WINDOWS_CONCURRENT_PROBE_LOGGING_OK'
} finally {
  if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
