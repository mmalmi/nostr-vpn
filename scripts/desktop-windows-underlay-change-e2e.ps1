param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("Initialize", "Run", "Probe", "WireGuardProbe", "Watchdog", "Cleanup")]
  [string]$Action,
  [Parameter(Mandatory = $true)]
  [string]$Binary,
  [Parameter(Mandatory = $true)]
  [string]$Config,
  [Parameter(Mandatory = $true)]
  [string]$StateDir,
  [string]$PrimaryMac,
  [string]$SecondaryMac,
  [string]$SecondaryAddress,
  [string]$SecondaryGateway,
  [int]$SecondaryPrefixLength = 24,
  [string]$NetworkId,
  [string]$PeerNpub,
  [string]$PeerEndpoint,
  [string]$PeerTunnelIp,
  [string]$WireGuardPeerPublicKey,
  [string]$WireGuardEndpoint,
  [string]$WireGuardClientAddress = "10.232.0.2/32",
  [string]$WireGuardServerIp,
  [string]$WireGuardInterface = "nvpn-wg-exit",
  [string]$FixtureDnsName = "underlay-gate.nvpn.test",
  [string]$ProbeUrl = "https://example.com/",
  [string]$ExpectedFipsVersion,
  [string]$ExpectedFipsRevision,
  [string]$TunnelInterface = "nvpn-underlay-gate",
  [int]$ListenPort = 45821,
  [int]$RecoveryDeadlineMilliseconds = 4000,
  [int]$RunnerPid = 0,
  [int]$WatchdogTimeoutSeconds = 300
)

# Production-path Windows underlay handoff gate. The host-side orchestrator
# gives this disposable VM a second physical NIC and cuts/restores the original
# virtual link. This script drives the shipped nvpn daemon, Wintun, route
# reconciliation, secure DNS, and continuous tunnel payload without a mock.
$ErrorActionPreference = "Stop"
$WireGuardPrivateKeyPath = Join-Path $StateDir "wireguard-client-private.key"
$WireGuardConfigPath = Join-Path $StateDir "wireguard-client.conf"
$CleanupJournalPath = Join-Path $StateDir "daemon.cleanup.json"

. (Join-Path $PSScriptRoot "desktop-windows-underlay-change-e2e.lib.ps1")
. (Join-Path $PSScriptRoot "desktop-windows-underlay-crash-recovery.lib.ps1")
function Protect-SecretFile {
  param([string]$Path)
  & icacls.exe $Path /inheritance:r `
    /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "could not restrict ACL on $Path"
  }
}

function New-WireGuardClientKey {
  $wg = Resolve-WireGuardTool "wg.exe"
  $privateKey = ([string](& $wg genkey)).Trim()
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($privateKey)) {
    throw "wg.exe genkey did not return a private key"
  }
  [IO.File]::WriteAllText(
    $WireGuardPrivateKeyPath,
    $privateKey + [Environment]::NewLine,
    [Text.Encoding]::ASCII
  )
  Protect-SecretFile $WireGuardPrivateKeyPath

  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $wg
  $startInfo.Arguments = "pubkey"
  $startInfo.UseShellExecute = $false
  $startInfo.RedirectStandardInput = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  if (!$process.Start()) {
    throw "could not start wg.exe pubkey"
  }
  $process.StandardInput.WriteLine($privateKey)
  $process.StandardInput.Close()
  $publicKey = $process.StandardOutput.ReadToEnd().Trim()
  $stderr = $process.StandardError.ReadToEnd().Trim()
  $process.WaitForExit()
  if ($process.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($publicKey)) {
    throw "wg.exe pubkey failed: $stderr"
  }
  return $publicKey
}

function Write-WireGuardConfig {
  if (!(Test-Path -LiteralPath $WireGuardPrivateKeyPath -PathType Leaf)) {
    throw "WireGuard client private key is missing"
  }
  $privateKey = (Get-Content -Raw -LiteralPath $WireGuardPrivateKeyPath).Trim()
  $text = @"
[Interface]
PrivateKey = $privateKey
Address = $WireGuardClientAddress
DNS = 1.1.1.1

[Peer]
PublicKey = $WireGuardPeerPublicKey
AllowedIPs = 0.0.0.0/0
Endpoint = $WireGuardEndpoint
PersistentKeepalive = 1
"@
  [IO.File]::WriteAllText(
    $WireGuardConfigPath,
    $text,
    [Text.Encoding]::ASCII
  )
  Protect-SecretFile $WireGuardConfigPath
}

function Test-PhysicalUnderlay {
  param([int]$InterfaceIndex)
  try {
    $adapter = Get-AdapterByIndex $InterfaceIndex
    $address = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex `
      -AddressFamily IPv4 -ErrorAction Stop |
      Where-Object {
        $_.AddressState -eq "Preferred" -and
        !$_.IPAddress.StartsWith("169.254.")
      })
    $defaultRoute = @(Get-NetRoute -InterfaceIndex $InterfaceIndex `
      -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" `
      -ErrorAction Stop)
    $selectedPhysicalIndex = Get-SelectedPhysicalDefaultInterfaceIndex
    return (
      $adapter.Status -eq "Up" -and
      $address.Count -gt 0 -and
      $defaultRoute.Count -gt 0 -and
      $selectedPhysicalIndex -eq $InterfaceIndex
    )
  }
  catch {
    return $false
  }
}

function Test-ExternalHttps {
  & curl.exe -4 --ssl-revoke-best-effort --fail --silent `
    --max-time 8 --output NUL $ProbeUrl
  return $LASTEXITCODE -eq 0
}

function Resolve-FixtureDns {
  try {
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    $addresses = [Net.Dns]::GetHostAddresses($FixtureDnsName) |
      Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } |
      ForEach-Object { $_.ToString() }
    return @($addresses)
  }
  catch {
    return @()
  }
}

function Test-FixtureDns {
  return @((Resolve-FixtureDns) | Where-Object { $_ -eq $PeerTunnelIp }).Count -gt 0
}

function Test-PublicDns {
  try {
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    $hostName = ([Uri]$ProbeUrl).DnsSafeHost
    $addresses = [Net.Dns]::GetHostAddresses($hostName) |
      Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork }
    return @($addresses).Count -gt 0
  }
  catch {
    return $false
  }
}

function Test-DnsName {
  param([string]$Name)
  try {
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    $addresses = [Net.Dns]::GetHostAddresses($Name) |
      Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork }
    return @($addresses).Count -gt 0
  }
  catch {
    return $false
  }
}

function Get-SecureDnsRules {
  return @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object {
      $_.DisplayName -eq "nostr-vpn secure DNS" -or
      $_.Comment -eq "nostr-vpn authenticated DNS-over-HTTPS stub"
    })
}

function Get-RebindReceiptCount {
  $log = Join-Path $StateDir "daemon.stderr.log"
  if (!(Test-Path -LiteralPath $log)) {
    return 0
  }
  return @(
    Select-String -Path $log `
      -SimpleMatch "underlay carrier(s) rebound" `
      -ErrorAction SilentlyContinue
  ).Count
}

function Get-ProbeSuccessCount {
  $log = Join-Path $StateDir "payload.log"
  if (!(Test-Path -LiteralPath $log)) {
    return 0
  }
  return @(
    Select-String -Path $log -Pattern "^OK " -ErrorAction SilentlyContinue
  ).Count
}

function Get-WireGuardProbeSuccessCount {
  $log = Join-Path $StateDir "wireguard-payload.log"
  if (!(Test-Path -LiteralPath $log)) {
    return 0
  }
  return @(
    Select-String -Path $log -Pattern "^OK " -ErrorAction SilentlyContinue
  ).Count
}

function Invoke-BoundedProbeProcess {
  param(
    [string]$FilePath,
    [string[]]$ArgumentList,
    [int]$TimeoutMilliseconds
  )
  $process = Start-Process -FilePath $FilePath `
    -ArgumentList $ArgumentList -WindowStyle Hidden -PassThru
  try {
    if (!$process.WaitForExit($TimeoutMilliseconds)) {
      Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
      if (!$process.WaitForExit(1000)) {
        throw "timed-out payload probe could not be terminated"
      }
      return $false
    }
    return $process.ExitCode -eq 0
  }
  finally {
    $process.Dispose()
  }
}

function Get-FirstTimestampedReceipt {
  param(
    [string]$LogName,
    [string]$Pattern,
    [int]$PriorCount,
    [long]$NotBeforeUnixMilliseconds
  )
  $log = Join-Path $StateDir $LogName
  if (!(Test-Path -LiteralPath $log)) { return 0 }
  $timestamps = @(
    Get-Content -LiteralPath $log -ErrorAction SilentlyContinue |
      ForEach-Object {
        if ($_ -match $Pattern) {
          [long]$Matches[1]
        }
      }
  )
  if ($timestamps.Count -le $PriorCount) { return 0 }
  $receipt = @(
    $timestamps |
      Select-Object -Skip $PriorCount |
      Where-Object { $_ -ge $NotBeforeUnixMilliseconds } |
      Select-Object -First 1
  )
  if ($receipt.Count -eq 0) { return 0 }
  [long]$receipt[0]
}

function Get-EndpointStartCount {
  $log = Join-Path $StateDir "daemon.stderr.log"
  if (!(Test-Path -LiteralPath $log)) {
    return 0
  }
  return @(
    Select-String -Path $log `
      -Pattern "daemon: (FIPS private mesh on|restarted FIPS private mesh on|rebuilt FIPS private mesh on)" `
      -ErrorAction SilentlyContinue
  ).Count
}

function Assert-SessionContinuity {
  param(
    [int]$ExpectedDaemonPid,
    [int]$ExpectedEndpointStartCount,
    [string]$ExpectedNpub,
    [string]$ExpectedTunnelIp
  )
  if ((Get-DaemonPid) -ne $ExpectedDaemonPid) {
    throw "daemon PID changed during the physical handoff"
  }
  if ((Read-Npub) -ne $ExpectedNpub) {
    throw "local identity changed during the physical handoff"
  }
  $currentTunnelIp = (& $Binary ip --config $Config).Trim()
  if ($LASTEXITCODE -ne 0 -or $currentTunnelIp -ne $ExpectedTunnelIp) {
    throw "tunnel IP changed during the physical handoff"
  }
  if ((Get-EndpointStartCount) -ne $ExpectedEndpointStartCount) {
    throw "FIPS endpoint restarted during the physical handoff"
  }
  $log = Join-Path $StateDir "daemon.stderr.log"
  if (
    (Test-Path -LiteralPath $log) -and
    (Select-String -Path $log `
      -Pattern "daemon: (restarted|rebuilt) FIPS private mesh on" `
      -Quiet -ErrorAction SilentlyContinue)
  ) {
    throw "FIPS endpoint was replaced during the physical handoff"
  }
  if (
    (Test-Path -LiteralPath $log) -and
    (Select-String -Path $log `
      -Pattern "EADDRNOTAVAIL|address not available|cannot assign requested address" `
      -Quiet -ErrorAction SilentlyContinue)
  ) {
    throw "FIPS reported an address-bind failure during the physical handoff"
  }
  Assert-ExpectedFipsRoster (Read-Status)
}

function Assert-ExpectedFipsRoster {
  param($Status)
  $configuredPeers = @($Status.daemon.state.fips_endpoint_peers)
  if (
    $configuredPeers.Count -ne 1 -or
    [string]$configuredPeers[0].npub -ne $PeerNpub
  ) {
    throw "live FIPS endpoint roster drifted from the one expected participant"
  }
}

function Wait-ForCondition {
  param(
    [string]$Description,
    [int]$TimeoutMilliseconds,
    [scriptblock]$Condition,
    [int]$PollMilliseconds = 50,
    [bool]$CancelAware = $false
  )
  $timer = [Diagnostics.Stopwatch]::StartNew()
  while ($timer.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
    if ($CancelAware) {
      Assert-NotCancelled
    }
    if (& $Condition) {
      return $timer.ElapsedMilliseconds
    }
    Start-Sleep -Milliseconds $PollMilliseconds
  }
  if ($CancelAware) {
    Assert-NotCancelled
  }
  # A receipt written at the deadline must not be lost between the last poll
  # and the elapsed-time check.
  if (& $Condition) {
    return $timer.ElapsedMilliseconds
  }
  throw "timed out after ${TimeoutMilliseconds}ms waiting for $Description"
}

function Test-CancelRequested {
  Test-Path -LiteralPath (Join-Path $StateDir "cancel")
}

function Assert-NotCancelled {
  if (Test-CancelRequested) {
    throw [OperationCanceledException]::new(
      "Windows underlay runner was cancelled by its host owner"
    )
  }
}

function Wait-ForFile {
  param([string]$Name)
  $path = Join-Path $StateDir $Name
  Wait-ForCondition "host signal $Name" 30000 {
    Test-Path -LiteralPath $path
  } 100 $true |
    Out-Null
}

function Write-Marker {
  param([string]$Name, [string]$Value = "ok")
  [IO.File]::WriteAllText(
    (Join-Path $StateDir $Name),
    $Value,
    [Text.UTF8Encoding]::new($false)
  )
}

function Test-ExpectedFipsCoreVersion {
  param([object]$Value)
  return (
    [string]$Value -eq "$ExpectedFipsVersion (rev $ExpectedFipsRevision)"
  )
}

function Assert-ActiveExit {
  param(
    [int]$ExpectedPhysicalIndex,
    [int]$ExpectedDaemonPid,
    [bool]$RequireFixtureDns = $true
  )
  $status = Read-Status
  if (
    $status.status_source -ne "daemon" -or
    !$status.daemon.running -or
    [int]$status.daemon.pid -ne $ExpectedDaemonPid -or
    !$status.daemon.state.mesh_ready -or
    [int]$status.daemon.state.connected_peer_count -lt 1 -or
    !(Test-ExpectedFipsCoreVersion $status.daemon.state.fips_core_version)
  ) {
    throw "nvpn daemon/mesh status is not ready or its PID changed"
  }
  Assert-ExpectedFipsRoster $status

  $internetRoute = Get-BestRoute "1.1.1.1"
  $wireGuard = Get-WireGuardAdapter
  if ([int]$internetRoute.InterfaceIndex -ne [int]$wireGuard.ifIndex) {
    throw "public Internet is not routed through the real WireGuard exit"
  }

  $endpointHost = Get-WireGuardEndpointHost
  $endpointRoute = Get-BestRoute $endpointHost
  if ([int]$endpointRoute.InterfaceIndex -ne $ExpectedPhysicalIndex) {
    throw "WireGuard endpoint bypass did not move to the expected physical underlay"
  }
  Assert-WireGuardEndpointRoute $ExpectedPhysicalIndex | Out-Null
  if (!(Test-WireGuardHandshake)) {
    throw "WireGuard exit has no successful handshake"
  }
  if ((Get-SecureDnsRules).Count -eq 0) {
    throw "nvpn secure DNS policy is missing while the exit is active"
  }
  if ($RequireFixtureDns -and !(Test-FixtureDns)) {
    throw "fixture name did not resolve through the selected exit DNS server"
  }
  if (!(Test-PublicDns) -or !(Test-ExternalHttps)) {
    throw "public DNS or verified HTTPS failed through the selected exit"
  }
}

function Wait-ForRecoveryEvidence {
  param(
    [string]$Label,
    [long]$ObservationStartedUnixMilliseconds,
    [long]$RouteUsableUnixMilliseconds,
    [int]$RebindBefore,
    [int]$ProbeBefore,
    [int]$WireGuardProbeBefore
  )
  $deadlineUnixMilliseconds =
    $RouteUsableUnixMilliseconds + $RecoveryDeadlineMilliseconds
  $deadlineEdgeRead = $false
  while ($true) {
    Assert-NotCancelled
    $rebindAfter = Get-RebindReceiptCount
    if ($rebindAfter -gt ($RebindBefore + 1)) {
      throw "$Label produced more than one FIPS carrier rebind"
    }
    if ($rebindAfter -eq ($RebindBefore + 1)) {
      $rebindAt = Get-FirstTimestampedReceipt "daemon.stderr.log" `
        "underlay carrier\(s\) rebound.*refreshed_unix_ms=([0-9]+)" `
        $RebindBefore $ObservationStartedUnixMilliseconds
      $payloadAt = Get-FirstTimestampedReceipt "payload.log" `
        "^OK ([0-9]+)$" $ProbeBefore $RouteUsableUnixMilliseconds
      $wireGuardPayloadAt = Get-FirstTimestampedReceipt `
        "wireguard-payload.log" "^OK ([0-9]+)$" `
        $WireGuardProbeBefore $RouteUsableUnixMilliseconds
      if ($rebindAt -gt 0 -and $payloadAt -gt 0 -and $wireGuardPayloadAt -gt 0) {
        $recoveredAt = [Math]::Max(
          $rebindAt,
          [Math]::Max($payloadAt, $wireGuardPayloadAt)
        )
        $elapsed = $recoveredAt - $RouteUsableUnixMilliseconds
        if ($recoveredAt -gt $deadlineUnixMilliseconds) {
          throw "$Label recovery exceeded ${RecoveryDeadlineMilliseconds}ms ($elapsed ms)"
        }
        return [PSCustomObject]@{
          rebind_unix_milliseconds = $rebindAt
          payload_success_unix_milliseconds = $payloadAt
          wireguard_payload_success_unix_milliseconds = $wireGuardPayloadAt
          recovered_unix_milliseconds = $recoveredAt
          rebind_receipts_after = $rebindAfter
        }
      }
    }
    if ($deadlineEdgeRead) {
      break
    }
    if (
      [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge
        $deadlineUnixMilliseconds
    ) {
      # One deadline-edge read accepts a delayed log write only when the
      # timestamped product evidence itself met the deadline.
      $deadlineEdgeRead = $true
    }
    else {
      Start-Sleep -Milliseconds 25
    }
  }
  throw (
    "timed out after ${RecoveryDeadlineMilliseconds}ms waiting for " +
    "$Label timestamped payload/FIPS recovery evidence"
  )
}

function Observe-Recovery {
  param(
    [string]$Label,
    [scriptblock]$NewUnderlayAvailable,
    [int]$ExpectedPhysicalIndex,
    [int]$ExpectedDaemonPid,
    [int]$ExpectedEndpointStartCount,
    [string]$ExpectedNpub,
    [string]$ExpectedTunnelIp,
    [long]$ObservationStartedUnixMilliseconds,
    [int]$RebindBefore
  )
  Wait-ForCondition "$Label physical underlay to become usable" `
    30000 $NewUnderlayAvailable 25 $true |
    Out-Null
  $routeUsableUnixMilliseconds = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $probeBefore = Get-ProbeSuccessCount
  $wireGuardProbeBefore = Get-WireGuardProbeSuccessCount

  $evidence = Wait-ForRecoveryEvidence `
    $Label `
    $ObservationStartedUnixMilliseconds `
    $routeUsableUnixMilliseconds `
    $rebindBefore `
    $probeBefore `
    $wireGuardProbeBefore

  # Stable state is still audited, but audit latency is deliberately excluded
  # from the product recovery measurement above.
  Assert-ActiveExit $ExpectedPhysicalIndex $ExpectedDaemonPid
  Assert-SessionContinuity `
    $ExpectedDaemonPid `
    $ExpectedEndpointStartCount `
    $ExpectedNpub `
    $ExpectedTunnelIp
  $rebindAfter = Get-RebindReceiptCount
  if ($rebindAfter -ne ($rebindBefore + 1)) {
    throw "$Label did not produce exactly one FIPS carrier rebind"
  }
  $wireGuardEndpointRoute = Assert-WireGuardEndpointRoute $ExpectedPhysicalIndex
  $elapsed = [long]$evidence.recovered_unix_milliseconds -
    $routeUsableUnixMilliseconds
  Write-Marker "$Label.receipt.json" (
    [PSCustomObject]@{
      recovery_milliseconds = $elapsed
      observation_started_unix_milliseconds =
        $ObservationStartedUnixMilliseconds
      route_usable_unix_milliseconds = $routeUsableUnixMilliseconds
      recovered_unix_milliseconds = $evidence.recovered_unix_milliseconds
      rebind_unix_milliseconds = $evidence.rebind_unix_milliseconds
      payload_success_unix_milliseconds =
        $evidence.payload_success_unix_milliseconds
      wireguard_payload_success_unix_milliseconds =
        $evidence.wireguard_payload_success_unix_milliseconds
      daemon_pid = $ExpectedDaemonPid
      physical_interface_index = $ExpectedPhysicalIndex
      identity_npub = $ExpectedNpub
      tunnel_ip = $ExpectedTunnelIp
      participant_npub = $PeerNpub
      endpoint_start_count = $ExpectedEndpointStartCount
      payload_successes_before = $probeBefore
      payload_successes_after = Get-ProbeSuccessCount
      wireguard_payload_successes_before = $wireGuardProbeBefore
      wireguard_payload_successes_after = Get-WireGuardProbeSuccessCount
      wireguard_endpoint_route = $wireGuardEndpointRoute
      rebind_receipts_before = $rebindBefore
      rebind_receipts_after = $evidence.rebind_receipts_after
    } | ConvertTo-Json -Compress
  )
}

function Run-DnsSettingCase {
  param(
    [string]$Name,
    [string[]]$SetArguments,
    [string]$LookupName,
    [int]$ExpectedDaemonPid,
    [int]$ExpectedPhysicalIndex
  )
  Wait-ForFile "dns-$Name.go"
  Invoke-Nvpn (@("set", "--config", $Config) + $SetArguments)
  Write-Marker "dns-$Name.configured" "ok"
  Wait-ForFile "dns-$Name.query"
  Wait-ForCondition "real $Name DNS lookup through the active exit" 30000 {
    try {
      $lookupOk = if ($LookupName -eq $FixtureDnsName) {
        Test-FixtureDns
      }
      else {
        Test-DnsName $LookupName
      }
      Assert-ActiveExit $ExpectedPhysicalIndex $ExpectedDaemonPid $false
      return $lookupOk
    }
    catch {
      return $false
    }
  } 250 $true | Out-Null
  Write-Marker "dns-$Name.receipt" $LookupName
}

function Restore-AdapterConfiguration {
  $statePath = Join-Path $StateDir "adapter-state.json"
  if (!(Test-Path -LiteralPath $statePath)) {
    return
  }
  $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
  $primary = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Where-Object {
      [int]$_.ifIndex -eq [int]$state.primary_interface_index
    } | Select-Object -First 1)
  if ($primary.Count -eq 1) {
    if ([string]$state.primary_automatic_metric -eq "Enabled") {
      Set-NetIPInterface -InterfaceIndex $primary.ifIndex -AddressFamily IPv4 `
        -AutomaticMetric Enabled -ErrorAction SilentlyContinue
    }
    else {
      Set-NetIPInterface -InterfaceIndex $primary.ifIndex -AddressFamily IPv4 `
        -AutomaticMetric Disabled -InterfaceMetric ([int]$state.primary_metric) `
        -ErrorAction SilentlyContinue
    }
  }
}

function Remove-ExitWireGuardService {
  $serviceName = 'WireGuardTunnel$' + $WireGuardInterface
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($service) {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName 2>$null | Out-Null
    Wait-ForCondition "WireGuard exit service removal" 5000 {
      !(Get-Service -Name $serviceName -ErrorAction SilentlyContinue)
    } 100 | Out-Null
  }
  Remove-Item -LiteralPath (
    Join-Path $env:ProgramData "nostr-vpn\wireguard\$WireGuardInterface.conf"
  ) -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $WireGuardConfigPath `
    -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $WireGuardPrivateKeyPath `
    -Force -ErrorAction SilentlyContinue
}

function Assert-IsolatedNetworkPreflight {
  $wireGuardService = 'WireGuardTunnel$' + $WireGuardInterface
  $nativeWireGuardRoot = Join-Path $env:ProgramData "nostr-vpn\wireguard"
  $stale = @(
    if (Get-Service -Name "NvpnService" -ErrorAction SilentlyContinue) {
      "NvpnService"
    }
    if (Get-Process -Name "nvpn" -ErrorAction SilentlyContinue) { "nvpn process" }
    Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -in @($TunnelInterface, $WireGuardInterface) } |
      ForEach-Object { "network adapter $($_.Name)" }
    if (Get-Service -Name $wireGuardService -ErrorAction SilentlyContinue) {
      "WireGuard service $wireGuardService"
    }
    if ((Get-SecureDnsRules).Count -ne 0) { "nvpn secure DNS policy" }
    if (Test-Path -LiteralPath $nativeWireGuardRoot) {
      Get-ChildItem -LiteralPath $nativeWireGuardRoot -Force -ErrorAction Stop |
        Select-Object -First 1 |
        ForEach-Object { "native WireGuard artifact root" }
    }
  )
  if ($stale.Count -ne 0) {
    throw ("Windows isolated network preflight found: " + ($stale -join "; "))
  }
}

function Invoke-IsolatedNetworkCleanup {
  param([switch]$EmergencyRepair, [int]$DaemonPid = 0)
  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  if ($DaemonPid -le 0) {
    try { $DaemonPid = Get-DaemonPid } catch { $DaemonPid = 0 }
  }
  & $Binary stop --config $Config --timeout-secs 5 --force 2>$null | Out-Null
  $stopExitCode = $LASTEXITCODE
  if ($DaemonPid -gt 0) {
    Stop-Process -Id $DaemonPid -Force -ErrorAction SilentlyContinue
    Wait-ForCondition "exact candidate daemon termination" 5000 {
      !(Get-Process -Id $DaemonPid -ErrorAction SilentlyContinue)
    } 50 | Out-Null
  }
  $failures = @()
  if ($stopExitCode -ne 0) {
    $failures += "normal nvpn stop failed with exit code $stopExitCode"
  }
  try {
    Assert-NativeNetworkRestoredBeforeRepair
  }
  catch {
    $failures += $_.Exception.Message
  }
  if ($failures.Count -gt 0 -and $EmergencyRepair) {
    Write-Marker "emergency-repair-invoked" ($failures -join "; ")
    & $Binary repair-network --config $Config 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
      $failures += "emergency repair-network failed with exit code $LASTEXITCODE"
    }
  }
  Remove-ExitWireGuardService
  Restore-AdapterConfiguration
  if ($failures.Count -gt 0) {
    throw ($failures -join "; ")
  }
}

function Invoke-OwnedNetworkCleanup {
  param(
    [string]$Owner,
    [int]$DaemonPid = 0,
    [int]$RunnerPidToStop = 0
  )
  if (!(Test-Path -LiteralPath (Join-Path $StateDir "cleanup-owned"))) {
    throw "guest cleanup was not authorized by a clean preflight"
  }
  $lock = $null
  $deadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
  while (!$lock) {
    try {
      $lock = [IO.File]::Open(
        (Join-Path $StateDir "cleanup.lock"),
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
      )
    }
    catch [IO.IOException] {
      if ([DateTimeOffset]::UtcNow -ge $deadline) {
        throw "timed out waiting for the active cleanup owner"
      }
      Start-Sleep -Milliseconds 100
    }
  }
  try {
    $failurePath = Join-Path $StateDir "cleanup.failed"
    if (Test-Path -LiteralPath $failurePath) {
      throw ("the prior cleanup owner failed: " +
        (Get-Content -Raw -LiteralPath $failurePath))
    }
    if (Test-Path -LiteralPath (Join-Path $StateDir "cleanup.complete")) {
      return
    }
    try {
      if (
        $RunnerPidToStop -gt 0 -and
        (Get-Process -Id $RunnerPidToStop -ErrorAction SilentlyContinue)
      ) {
        Stop-Process -Id $RunnerPidToStop -Force -ErrorAction Stop
        Wait-Process -Id $RunnerPidToStop -Timeout 5 -ErrorAction SilentlyContinue
        if (Get-Process -Id $RunnerPidToStop -ErrorAction SilentlyContinue) {
          throw "cleanup owner could not stop the Windows guest runner"
        }
      }
      Write-Marker "stop-probe"
      Write-Marker "watchdog.complete"
      foreach ($marker in @("probe.pid", "wireguard-probe.pid", "watchdog.pid")) {
        $processPath = Join-Path $StateDir $marker
        if (!(Test-Path -LiteralPath $processPath)) { continue }
        $processId = [int](Get-Content -Raw -LiteralPath $processPath)
        if ($processId -eq $PID) { continue }
        Wait-Process -Id $processId -Timeout 3 -ErrorAction SilentlyContinue
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
          throw "cleanup owner could not stop recorded process $marker"
        }
      }
      Invoke-IsolatedNetworkCleanup -EmergencyRepair -DaemonPid $DaemonPid
      Write-Marker "cleanup.complete" $Owner
    }
    catch {
      Write-Marker "cleanup.failed" ($Owner + ": " + $_.Exception.Message)
      throw
    }
  }
  finally {
    $lock.Dispose()
  }
}

Assert-Administrator

switch ($Action) {
  "Initialize" {
    foreach ($value in @(
      $PrimaryMac,
      $SecondaryMac,
      $SecondaryAddress,
      $SecondaryGateway,
      $NetworkId
    )) {
      if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Initialize is missing a required underlay/config argument"
      }
    }
    if (!(Test-Path -LiteralPath $Binary -PathType Leaf)) {
      throw "candidate nvpn binary does not exist"
    }
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    Get-ChildItem -LiteralPath $StateDir -Force -ErrorAction SilentlyContinue |
      Remove-Item -Recurse -Force

    $primary = Get-AdapterByMac $PrimaryMac
    $secondary = Get-AdapterByMac $SecondaryMac
    $primaryIp = Get-NetIPInterface -InterfaceIndex $primary.ifIndex `
      -AddressFamily IPv4 -ErrorAction Stop
    [PSCustomObject]@{
      primary_interface_index = [int]$primary.ifIndex
      secondary_interface_index = [int]$secondary.ifIndex
      primary_metric = [int]$primaryIp.InterfaceMetric
      primary_automatic_metric = [string]$primaryIp.AutomaticMetric
    } | ConvertTo-Json -Compress |
      Set-Content -LiteralPath (Join-Path $StateDir "adapter-state.json") `
        -Encoding ASCII

    Assert-IsolatedNetworkPreflight
    Write-Marker "cleanup-owned" "clean preflight"

    Enable-NetAdapter -Name $secondary.Name -Confirm:$false
    Set-NetIPInterface -InterfaceIndex $primary.ifIndex -AddressFamily IPv4 `
      -AutomaticMetric Disabled -InterfaceMetric 10
    Set-NetIPInterface -InterfaceIndex $secondary.ifIndex -AddressFamily IPv4 `
      -Dhcp Disabled -AutomaticMetric Disabled -InterfaceMetric 600
    Get-NetRoute -InterfaceIndex $secondary.ifIndex -AddressFamily IPv4 `
      -ErrorAction SilentlyContinue |
      Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetIPAddress -InterfaceIndex $secondary.ifIndex -AddressFamily IPv4 `
      -ErrorAction SilentlyContinue |
      Where-Object { $_.PrefixOrigin -ne "WellKnown" } |
      Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $secondary.ifIndex `
      -IPAddress $SecondaryAddress `
      -PrefixLength $SecondaryPrefixLength `
      -DefaultGateway $SecondaryGateway |
      Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $secondary.ifIndex `
      -ServerAddresses @("1.1.1.1")

    Invoke-Nvpn @("init", "--config", $Config, "--force")
    Invoke-Nvpn @("set", "--config", $Config, "--network-id", $NetworkId)
    $npub = Read-Npub
    $tunnelIp = (& $Binary ip --config $Config).Trim()
    if ($LASTEXITCODE -ne 0 -or !$tunnelIp) {
      throw "could not derive the Windows tunnel IP"
    }
    $wireGuardPublicKey = New-WireGuardClientKey
    $primaryAddress = Get-PreferredIPv4Address ([int]$primary.ifIndex)
    $primaryDefault = Get-PhysicalDefaultRoute ([int]$primary.ifIndex)
    [PSCustomObject]@{
      npub = $npub
      tunnel_ip = $tunnelIp
      primary_interface_index = [int]$primary.ifIndex
      secondary_interface_index = [int]$secondary.ifIndex
      primary_address = [string]$primaryAddress.IPAddress
      primary_gateway = [string]$primaryDefault.NextHop
      wireguard_public_key = $wireGuardPublicKey
    } | ConvertTo-Json -Compress
  }

  "Probe" {
    Write-Marker "probe.pid" "$PID"
    if ([string]::IsNullOrWhiteSpace($PeerTunnelIp)) {
      throw "Probe requires PeerTunnelIp"
    }
    $log = Join-Path $StateDir "payload.log"
    while (!(Test-Path -LiteralPath (Join-Path $StateDir "stop-probe"))) {
      try {
        $ok = Invoke-BoundedProbeProcess "$env:SystemRoot\System32\PING.EXE" `
          @("-n", "1", "-w", "750", "-l", "32", $PeerTunnelIp) 1500
        $completedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        if ($ok) {
          Add-Content -LiteralPath $log -Value "OK $completedAt" -Encoding ASCII
        }
        else {
          Add-Content -LiteralPath $log `
            -Value "FAIL $completedAt" -Encoding ASCII
        }
      }
      catch {
        $completedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        Add-Content -LiteralPath $log `
          -Value "FAIL $completedAt exception" -Encoding ASCII
      }
      Start-Sleep -Milliseconds 100
    }
  }

  "WireGuardProbe" {
    Write-Marker "wireguard-probe.pid" "$PID"
    $log = Join-Path $StateDir "wireguard-payload.log"
    while (!(Test-Path -LiteralPath (Join-Path $StateDir "stop-probe"))) {
      try {
        $ok = Invoke-BoundedProbeProcess "curl.exe" @(
          "-4", "--ssl-revoke-best-effort", "--fail", "--silent",
          "--max-time", "2", "--output", "NUL", $ProbeUrl
        ) 2500
        $completedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        if ($ok) {
          Add-Content -LiteralPath $log -Value "OK $completedAt" -Encoding ASCII
        }
        else {
          Add-Content -LiteralPath $log -Value "FAIL $completedAt" -Encoding ASCII
        }
      }
      catch {
        $completedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        Add-Content -LiteralPath $log -Value "FAIL $completedAt" -Encoding ASCII
      }
      Start-Sleep -Milliseconds 100
    }
  }

  "Watchdog" {
    Write-Marker "watchdog.pid" "$PID"
    if ($RunnerPid -le 0) {
      throw "Watchdog requires RunnerPid"
    }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($WatchdogTimeoutSeconds)
    $complete = Join-Path $StateDir "watchdog.complete"
    while (
      [DateTimeOffset]::UtcNow -lt $deadline -and
      (Get-Process -Id $RunnerPid -ErrorAction SilentlyContinue) -and
      !(Test-Path -LiteralPath $complete)
    ) {
      Start-Sleep -Milliseconds 500
    }
    if (!(Test-Path -LiteralPath $complete)) {
      Invoke-OwnedNetworkCleanup -Owner "watchdog" `
        -RunnerPidToStop $RunnerPid
    }
  }

  "Run" {
    Write-Marker "runner.pid" "$PID"
    Assert-NotCancelled
    foreach ($value in @(
      $PrimaryMac,
      $SecondaryMac,
      $NetworkId,
      $PeerNpub,
      $PeerEndpoint,
      $PeerTunnelIp,
      $WireGuardPeerPublicKey,
      $WireGuardEndpoint,
      $WireGuardClientAddress,
      $WireGuardServerIp,
      $WireGuardInterface,
      $ExpectedFipsVersion,
      $ExpectedFipsRevision
    )) {
      if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Run is missing a required peer/underlay argument"
      }
    }
    $primary = Get-AdapterByMac $PrimaryMac
    $secondary = Get-AdapterByMac $SecondaryMac
    $daemon = $null
    $probe = $null
    $wireGuardProbe = $null
    $watchdog = $null
    $runError = $cleanupError = $null
    try {
      Remove-Item -LiteralPath (Join-Path $StateDir "watchdog.complete") `
        -Force -ErrorAction SilentlyContinue
      $watchdogArgs = @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-Action", "Watchdog",
        "-Binary", $Binary,
        "-Config", $Config,
        "-StateDir", $StateDir,
        "-RunnerPid", "$PID",
        "-WatchdogTimeoutSeconds", "$WatchdogTimeoutSeconds"
      )
      $watchdog = Start-Process -FilePath "powershell.exe" `
        -ArgumentList $watchdogArgs -WindowStyle Hidden -PassThru
      Write-Marker "watchdog.pid" "$($watchdog.Id)"

      Write-WireGuardConfig
      Invoke-Nvpn @(
        "set", "--config", $Config,
        "--network-id", $NetworkId,
        "--participant", $PeerNpub,
        "--listen-port", "$ListenPort",
        "--fips-advertise-public-endpoint", "false",
        "--fips-nostr-discovery-enabled", "false",
        "--lan-discovery-enabled", "false",
        "--fips-webrtc-enabled", "false",
        "--fips-bootstrap-enabled", "false",
        "--fips-peer-endpoint", "${PeerNpub}=${PeerEndpoint}",
        "--wireguard-exit-config-file", $WireGuardConfigPath,
        "--wireguard-exit-interface", $WireGuardInterface,
        "--wireguard-exit-enabled", "true",
        "--exit-node-leak-protection", "true",
        "--exit-dns-mode", "through_exit",
        "--exit-dns-through-exit-servers", $WireGuardServerIp,
        "--autoconnect", "true"
      )

      $daemon = Start-CandidateDaemon "daemon"

      Wait-ForCondition "candidate daemon PID file" 30000 {
        try { (Get-DaemonPid) -eq $daemon.Id } catch { $false }
      } 100 $true | Out-Null
      $daemonPid = Get-DaemonPid
      $identityNpub = Read-Npub
      $tunnelIp = (& $Binary ip --config $Config).Trim()
      if ($LASTEXITCODE -ne 0 -or !$tunnelIp) {
        throw "could not read the running Windows tunnel IP"
      }
      Wait-ForCondition "single FIPS endpoint start receipt" 30000 {
        (Get-EndpointStartCount) -eq 1
      } 50 $true | Out-Null
      $endpointStartCount = Get-EndpointStartCount

      $probeArgs = @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-Action", "Probe",
        "-Binary", $Binary,
        "-Config", $Config,
        "-StateDir", $StateDir,
        "-PeerTunnelIp", $PeerTunnelIp
      )
      $probe = Start-Process -FilePath "powershell.exe" -ArgumentList $probeArgs `
        -WindowStyle Hidden -PassThru

      $wireGuardProbeArgs = @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-Action", "WireGuardProbe",
        "-Binary", $Binary,
        "-Config", $Config,
        "-StateDir", $StateDir,
        "-ProbeUrl", $ProbeUrl
      )
      $wireGuardProbe = Start-Process -FilePath "powershell.exe" `
        -ArgumentList $wireGuardProbeArgs -WindowStyle Hidden -PassThru

      Wait-ForCondition "initial FIPS, WireGuard exit, DNS, HTTPS, and payload" 30000 {
        try {
          Assert-ActiveExit ([int]$primary.ifIndex) $daemonPid
          return (
            (Get-ProbeSuccessCount) -gt 2 -and
            (Get-WireGuardProbeSuccessCount) -gt 1
          )
        }
        catch {
          Write-Marker "last-condition-error.txt" $_.Exception.Message
          return $false
        }
      } 250 $true | Out-Null
      Assert-NativeWireGuardSecretAcl
      Write-Marker "ready" "$daemonPid"

      Wait-ForFile "arm-secondary"
      $secondaryObservationStarted =
        [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
      $secondaryRebindBefore = Get-RebindReceiptCount
      Write-Marker "armed-secondary"
      Observe-Recovery "secondary" {
        (Get-AdapterByIndex ([int]$primary.ifIndex)).Status -ne "Up" -and
        (Test-PhysicalUnderlay ([int]$secondary.ifIndex))
      } ([int]$secondary.ifIndex) $daemonPid $endpointStartCount `
        $identityNpub $tunnelIp $secondaryObservationStarted `
        $secondaryRebindBefore

      Wait-ForFile "arm-primary"
      $primaryObservationStarted =
        [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
      $primaryRebindBefore = Get-RebindReceiptCount
      Write-Marker "armed-primary"
      Observe-Recovery "primary" {
        Test-PhysicalUnderlay ([int]$primary.ifIndex)
      } ([int]$primary.ifIndex) $daemonPid $endpointStartCount `
        $identityNpub $tunnelIp $primaryObservationStarted `
        $primaryRebindBefore

      Run-DnsSettingCase "automatic" @(
        "--exit-dns-mode", "automatic"
      ) "example.com" $daemonPid ([int]$primary.ifIndex)
      Run-DnsSettingCase "cloudflare" @(
        "--exit-dns-mode", "encrypted",
        "--exit-dns-doh-provider", "cloudflare"
      ) "www.cloudflare.com" $daemonPid ([int]$primary.ifIndex)
      Run-DnsSettingCase "quad9" @(
        "--exit-dns-mode", "encrypted",
        "--exit-dns-doh-provider", "quad9"
      ) "www.quad9.net" $daemonPid ([int]$primary.ifIndex)
      Run-DnsSettingCase "custom" @(
        "--exit-dns-mode", "encrypted",
        "--exit-dns-doh-provider", "custom",
        "--exit-dns-custom-doh-url", "https://dns.google/dns-query",
        "--exit-dns-custom-doh-bootstrap-ips", "8.8.8.8,8.8.4.4"
      ) "iana.org" $daemonPid ([int]$primary.ifIndex)
      Run-DnsSettingCase "through-exit" @(
        "--exit-dns-mode", "through_exit",
        "--exit-dns-through-exit-servers", $WireGuardServerIp
      ) $FixtureDnsName $daemonPid ([int]$primary.ifIndex)

      Wait-ForFile "select-direct"
      $daemon = Invoke-CrashRecovery `
        $daemon `
        ([int]$primary.ifIndex) `
        $identityNpub `
        $tunnelIp
      Write-Marker "done"
    }
    catch { $runError = $_ }
    finally {
      $cleanupDaemonPid = if ($daemon) { [int]$daemon.Id } else { 0 }
      try {
        Invoke-OwnedNetworkCleanup -Owner "runner" `
          -DaemonPid $cleanupDaemonPid
      } catch {
        $cleanupError = $_
      }
      Remove-Item -LiteralPath (Join-Path $StateDir "runner.pid") `
        -Force -ErrorAction SilentlyContinue
    }
    if ($runError) {
      if ($cleanupError) {
        [Console]::Error.WriteLine("cleanup also failed: " +
          $cleanupError.Exception.Message)
      }
      throw $runError
    }
    if ($cleanupError) { throw $cleanupError }
  }

  "Cleanup" {
    Invoke-OwnedNetworkCleanup -Owner "host" `
      -RunnerPidToStop $RunnerPid
  }
}
