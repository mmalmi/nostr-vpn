# Power-loss recovery assertions for the production Windows underlay gate.
# Dot-sourced after the run-scoped paths and common network helpers are loaded.

$script:CandidateNativeWireGuardConfigPath = ""
$script:CandidateNativeWireGuardOwnerMarkerPath = ""
$script:CandidateNativeWireGuardOwnerDirectoryPath = ""
$script:CandidateNativeWireGuardConfigRootPath = ""
$script:CandidateNativeWireGuardOwnerToken = ""

function Start-CandidateDaemon {
  param([string]$LogStem)
  $process = Start-Process -FilePath $Binary -ArgumentList @(
    "daemon",
    "--config", $Config,
    "--iface", $TunnelInterface,
    "--mesh-refresh-interval-secs", "2"
  ) -RedirectStandardOutput (Join-Path $StateDir "$LogStem.stdout.log") `
    -RedirectStandardError (Join-Path $StateDir "$LogStem.stderr.log") `
    -WindowStyle Hidden -PassThru
  return $process
}

function Assert-SingleExactCandidateDaemon {
  param([int]$ExpectedPid)
  $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'nvpn.exe'")
  if ($processes.Count -ne 1) {
    throw "expected exactly one nvpn daemon after restart, found $($processes.Count)"
  }
  $process = $processes[0]
  $expectedPath = [IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $Binary -ErrorAction Stop).Path
  )
  $actualPath = [IO.Path]::GetFullPath([string]$process.ExecutablePath)
  if (
    [int]$process.ProcessId -ne $ExpectedPid -or
    ![string]::Equals(
      $actualPath,
      $expectedPath,
      [StringComparison]::OrdinalIgnoreCase
    ) -or
    !([string]$process.CommandLine).Contains("daemon") -or
    !([string]$process.CommandLine).Contains($Config)
  ) {
    throw "the one post-restart nvpn process is not the exact candidate daemon"
  }

  $status = Read-Status
  if (
    $status.status_source -ne "daemon" -or
    !$status.daemon.running -or
    [int]$status.daemon.pid -ne $ExpectedPid -or
    !$status.daemon.state.mesh_ready -or
    [int]$status.daemon.state.connected_peer_count -lt 1 -or
    !(Test-ExpectedFipsCoreVersion $status.daemon.state.fips_core_version)
  ) {
    throw "the exact restarted candidate daemon/FIPS session is not ready"
  }
  Assert-ExpectedFipsRoster $status
}

function Read-CandidateNativeWireGuardOwnership {
  $journal = Get-Content -Raw -LiteralPath $CleanupJournalPath |
    ConvertFrom-Json
  $nativeEntries = @($journal.native_wireguard)
  if ($nativeEntries.Count -ne 1) {
    throw (
      "expected exactly one journaled native WireGuard owner, found {0}" -f
      $nativeEntries.Count
    )
  }
  $native = $nativeEntries[0]
  if (
    [string]$native.name -ne $WireGuardInterface -or
    $native.service_owned -ne $true -or
    $native.config_owned -ne $true -or
    [string]::IsNullOrWhiteSpace([string]$native.config_path) -or
    [string]::IsNullOrWhiteSpace([string]$native.owner_token)
  ) {
    throw "cleanup journal lacks exact native WireGuard ownership"
  }

  $configRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData "nostr-vpn\wireguard")
  ).TrimEnd("\")
  $configPath = [IO.Path]::GetFullPath([string]$native.config_path)
  $ownerDirectory = [IO.Path]::GetDirectoryName($configPath)
  $actualRoot = [IO.Path]::GetDirectoryName($ownerDirectory)
  $ownerToken = [string]$native.owner_token
  if (
    ![string]::Equals(
      $actualRoot,
      $configRoot,
      [StringComparison]::OrdinalIgnoreCase
    ) -or
    [IO.Path]::GetFileName($ownerDirectory) -ne $ownerToken -or
    [IO.Path]::GetFileName($configPath) -ne "$WireGuardInterface.conf"
  ) {
    throw "native WireGuard config is not in its exact owner directory"
  }
  $markerPath = "$configPath.nvpn-owner"
  foreach ($path in @($configRoot, $ownerDirectory)) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (
      !$item.PSIsContainer -or
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
      throw "native WireGuard ownership traverses a reparse point: $path"
    }
  }
  foreach ($path in @($configPath, $markerPath)) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (
      $item.PSIsContainer -or
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
      throw "native WireGuard ownership traverses a reparse point: $path"
    }
  }
  if (
    (Get-Content -Raw -LiteralPath $markerPath -ErrorAction Stop) -ne
      $ownerToken
  ) {
    throw "native WireGuard owner marker does not match the cleanup journal"
  }

  $script:CandidateNativeWireGuardConfigRootPath = $configRoot
  $script:CandidateNativeWireGuardConfigPath = $configPath
  $script:CandidateNativeWireGuardOwnerMarkerPath = $markerPath
  $script:CandidateNativeWireGuardOwnerDirectoryPath = $ownerDirectory
  $script:CandidateNativeWireGuardOwnerToken = $ownerToken
}

function Assert-CandidateNativeWireGuardOwnershipPresent {
  foreach ($path in @(
    $script:CandidateNativeWireGuardOwnerDirectoryPath,
    $script:CandidateNativeWireGuardConfigPath,
    $script:CandidateNativeWireGuardOwnerMarkerPath
  )) {
    if (!(Test-Path -LiteralPath $path)) {
      throw "candidate-owned native WireGuard artifact disappeared: $path"
    }
  }
  if (
    (Get-Content -Raw `
      -LiteralPath $script:CandidateNativeWireGuardOwnerMarkerPath) -ne
      $script:CandidateNativeWireGuardOwnerToken
  ) {
    throw "candidate native WireGuard marker changed after the crash"
  }
}

function Assert-CandidateNativeWireGuardOwnershipRemoved {
  foreach ($path in @(
    $script:CandidateNativeWireGuardConfigPath,
    $script:CandidateNativeWireGuardOwnerMarkerPath,
    $script:CandidateNativeWireGuardOwnerDirectoryPath
  )) {
    if (Test-Path -LiteralPath $path) {
      throw "candidate-owned native WireGuard artifact remains: $path"
    }
  }
}

function Assert-CrashRecoveredDirectState {
  param(
    [int]$ExpectedPhysicalIndex,
    [int]$ExpectedDaemonPid
  )
  $route = Get-BestRoute "1.1.1.1"
  $endpointHost = Get-WireGuardEndpointHost
  $endpointRoutes = @(Get-NetRoute -AddressFamily IPv4 `
    -DestinationPrefix "$endpointHost/32" `
    -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
  $wireGuardService = Get-Service `
    -Name ('WireGuardTunnel$' + $WireGuardInterface) `
    -ErrorAction SilentlyContinue
  $wireGuardAdapter = Get-NetAdapter -Name $WireGuardInterface `
    -IncludeHidden -ErrorAction SilentlyContinue
  $secureDnsRules = @(Get-SecureDnsRules)
  $publicDnsAvailable = Test-PublicDns
  $externalHttpsAvailable = Test-ExternalHttps
  $failures = [Collections.Generic.List[string]]::new()
  if ([int]$route.InterfaceIndex -ne $ExpectedPhysicalIndex) {
    $failures.Add(
      "best route interface $($route.InterfaceIndex) is not physical interface $ExpectedPhysicalIndex"
    )
  }
  if ($wireGuardAdapter) {
    $failures.Add("native WireGuard adapter remains")
  }
  if ($wireGuardService) {
    $failures.Add("native WireGuard service remains")
  }
  if ($endpointRoutes.Count -ne 0) {
    $failures.Add("endpoint bypass route remains ($($endpointRoutes.Count))")
  }
  if ($secureDnsRules.Count -ne 0) {
    $failures.Add("secure DNS policy remains ($($secureDnsRules.Count))")
  }
  if (Test-Path -LiteralPath $CleanupJournalPath) {
    $failures.Add("cleanup journal remains")
  }
  if (!$publicDnsAvailable) {
    $failures.Add("public DNS is unavailable")
  }
  if (!$externalHttpsAvailable) {
    $failures.Add("verified HTTPS is unavailable")
  }
  if ($failures.Count -ne 0) {
    throw (
      "startup recovery has not restored a clean native Direct network: " +
      ($failures -join "; ")
    )
  }
  Assert-CandidateNativeWireGuardOwnershipRemoved
  Assert-SingleExactCandidateDaemon $ExpectedDaemonPid
}

function Invoke-CrashRecovery {
  param(
    [Diagnostics.Process]$Daemon,
    [int]$ExpectedPhysicalIndex,
    [string]$ExpectedNpub,
    [string]$ExpectedTunnelIp
  )
  $crashedPid = [int]$Daemon.Id
  Assert-ActiveExit $ExpectedPhysicalIndex $crashedPid
  Wait-ForCondition "durable cleanup journal before forced termination" 5000 {
    try {
      $journal = Get-Item -LiteralPath $CleanupJournalPath -ErrorAction Stop
      return $journal.Length -gt 0
    }
    catch {
      return $false
    }
  } 50 | Out-Null
  $cleanupJournalHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $CleanupJournalPath
  ).Hash.ToLowerInvariant()
  Read-CandidateNativeWireGuardOwnership
  Assert-CandidateNativeWireGuardOwnershipPresent

  Stop-Process -Id $crashedPid -Force -ErrorAction Stop
  Wait-ForCondition "forced candidate daemon termination" 5000 {
    !(Get-Process -Id $crashedPid -ErrorAction SilentlyContinue)
  } 50 | Out-Null
  $cleanupJournalHashAfterCrash = if (
    Test-Path -LiteralPath $CleanupJournalPath -PathType Leaf
  ) {
    $journalHash = Get-FileHash -Algorithm SHA256 `
      -LiteralPath $CleanupJournalPath
    $journalHash.Hash.ToLowerInvariant()
  }
  else {
    ""
  }
  if ($cleanupJournalHashAfterCrash -ne $cleanupJournalHash) {
    throw "durable cleanup journal did not survive forced daemon termination"
  }
  Assert-CandidateNativeWireGuardOwnershipPresent
  if (@(Get-CimInstance Win32_Process -Filter "Name = 'nvpn.exe'").Count -ne 0) {
    throw "an nvpn process survived forced candidate daemon termination"
  }
  $wireGuard = Get-WireGuardAdapter
  $routeAfterCrash = Get-BestRoute "1.1.1.1"
  $wireGuardServiceAfterCrash = Get-Service `
    -Name ('WireGuardTunnel$' + $WireGuardInterface) `
    -ErrorAction SilentlyContinue
  if (
    [int]$routeAfterCrash.InterfaceIndex -ne [int]$wireGuard.ifIndex -or
    !$wireGuardServiceAfterCrash -or
    (Get-SecureDnsRules).Count -eq 0
  ) {
    throw "WireGuard exit routing/DNS policy was not still installed after the crash"
  }

  Invoke-Nvpn @(
    "set", "--config", $Config,
    "--wireguard-exit-enabled", "false",
    "--exit-dns-mode", "automatic"
  ) | Out-Null
  if (@(Get-CimInstance Win32_Process -Filter "Name = 'nvpn.exe'").Count -ne 0) {
    throw "selecting Direct while stopped unexpectedly left an nvpn process"
  }
  if (
    !(Test-Path -LiteralPath $CleanupJournalPath -PathType Leaf)
  ) {
    throw "offline Direct selection unexpectedly changed the cleanup journal"
  }
  $cleanupJournalHashAfterSelection = Get-FileHash -Algorithm SHA256 `
    -LiteralPath $CleanupJournalPath
  if (
    $cleanupJournalHashAfterSelection.Hash.ToLowerInvariant() -ne
      $cleanupJournalHash
  ) {
    throw "offline Direct selection unexpectedly changed the cleanup journal"
  }

  $recoveryTimer = [Diagnostics.Stopwatch]::StartNew()
  $replacement = Start-CandidateDaemon "daemon.restart"
  Wait-ForCondition "power-loss startup recovery to native Direct" 30000 {
    if ($replacement.HasExited) {
      $restartErrorPath = Join-Path $StateDir "daemon.restart.stderr.log"
      $restartError = if (Test-Path -LiteralPath $restartErrorPath) {
        (Get-Content -Raw -LiteralPath $restartErrorPath).Trim()
      } else {
        "<missing restart stderr>"
      }
      $message = (
        "replacement daemon exited with code {0}: {1}" -f
        $replacement.ExitCode,
        $restartError
      )
      Write-Marker "last-crash-recovery-error.txt" $message
      throw $message
    }
    try {
      Assert-CrashRecoveredDirectState `
        $ExpectedPhysicalIndex `
        ([int]$replacement.Id)
      return $true
    }
    catch {
      Write-Marker "last-crash-recovery-error.txt" $_.Exception.Message
      return $false
    }
  } 250 | Out-Null
  $recoveryMilliseconds = [int]$recoveryTimer.ElapsedMilliseconds

  if ((Read-Npub) -ne $ExpectedNpub) {
    throw "local identity changed across forced daemon restart"
  }
  $currentTunnelIp = (& $Binary ip --config $Config).Trim()
  if ($LASTEXITCODE -ne 0 -or $currentTunnelIp -ne $ExpectedTunnelIp) {
    throw "tunnel IP changed across forced daemon restart"
  }
  Remove-Item -LiteralPath $WireGuardConfigPath `
    -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $WireGuardPrivateKeyPath `
    -Force -ErrorAction SilentlyContinue

  $receipt = [PSCustomObject]@{
    crashed_daemon_pid = $crashedPid
    replacement_daemon_pid = [int]$replacement.Id
    daemon_process_count = 1
    exact_candidate_binary_restarted = $true
    cleanup_journal_present_before_crash = $true
    cleanup_journal_survived_forced_termination = $true
    cleanup_journal_sha256 = $cleanupJournalHash
    cleanup_journal_removed_after_restart = $true
    native_wireguard_config_path = $script:CandidateNativeWireGuardConfigPath
    native_wireguard_owner_marker_path =
      $script:CandidateNativeWireGuardOwnerMarkerPath
    native_wireguard_owner_directory_path =
      $script:CandidateNativeWireGuardOwnerDirectoryPath
    native_wireguard_owner_directory_layout = $true
    native_wireguard_owned_files_survived_forced_termination = $true
    native_wireguard_owned_files_removed_after_restart = $true
    selected_direct_while_daemon_stopped = $true
    startup_recovery_milliseconds = $recoveryMilliseconds
    physical_interface_index = $ExpectedPhysicalIndex
    identity_npub = $ExpectedNpub
    tunnel_ip = $ExpectedTunnelIp
    participant_npub = $PeerNpub
    wireguard_exit_state_remained_installed_after_crash = $true
    dns_policy_remained_installed_after_crash = $true
    wireguard_interface_removed = $true
    wireguard_endpoint_route_removed = $true
    wireguard_service_removed = $true
    wireguard_source_secrets_removed = $true
    public_dns = $true
    verified_https = $true
  } | ConvertTo-Json -Compress
  Write-Marker "crash-recovery.receipt.json" $receipt
  Write-Marker "direct.receipt.json" $receipt
  return $replacement
}
