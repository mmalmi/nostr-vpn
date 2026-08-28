# Transport, route, and WireGuard inspection helpers for the Windows guest gate.
# Dot-sourced after the main script initializes its run-scoped paths.

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Windows underlay network-change e2e requires an elevated SSH session"
  }
}

function Normalize-Mac {
  param([string]$Value)
  return ($Value -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
}

function Get-AdapterByMac {
  param([string]$Mac)
  $normalized = Normalize-Mac $Mac
  $matches = @(Get-NetAdapter -IncludeHidden |
    Where-Object { (Normalize-Mac ([string]$_.MacAddress)) -eq $normalized })
  if ($matches.Count -ne 1) {
    throw "expected exactly one Windows adapter with the supplied MAC, found $($matches.Count)"
  }
  return $matches[0]
}

function Get-AdapterByIndex {
  param([int]$Index)
  $matches = @(Get-NetAdapter -IncludeHidden |
    Where-Object { [int]$_.ifIndex -eq $Index })
  if ($matches.Count -ne 1) {
    throw "expected exactly one Windows adapter with interface index $Index, found $($matches.Count)"
  }
  return $matches[0]
}

function Invoke-Nvpn {
  param([string[]]$Arguments)
  & $Binary @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "nvpn command failed with exit code $LASTEXITCODE"
  }
}

function Read-Npub {
  $match = Select-String -Path $Config -Pattern '^public_key\s*=\s*"([^"]+)"' |
    Select-Object -First 1
  if (!$match) {
    throw "generated nvpn config has no public_key"
  }
  return $match.Matches[0].Groups[1].Value
}

function Read-Status {
  $raw = & $Binary status --config $Config --json --discover-secs 0
  if ($LASTEXITCODE -ne 0) {
    throw "nvpn status failed with exit code $LASTEXITCODE"
  }
  return ($raw | ConvertFrom-Json)
}

function Get-DaemonPid {
  $status = Read-Status
  if (!$status.daemon.running -or !$status.daemon.pid) {
    throw "candidate nvpn daemon is not running"
  }
  return [int]$status.daemon.pid
}

function Get-BestRoute {
  param([string]$RemoteAddress)
  $decision = @(Find-NetRoute -RemoteIPAddress $RemoteAddress -ErrorAction Stop)
  $route = @($decision | Where-Object {
    $_.PSObject.Properties.Name -contains "DestinationPrefix"
  } | Select-Object -First 1)
  $source = @($decision | Where-Object {
    $_.PSObject.Properties.Name -contains "IPAddress"
  } | Select-Object -First 1)
  if ($route.Count -ne 1 -or $source.Count -ne 1) {
    throw "Windows did not return one route and source decision for $RemoteAddress"
  }
  if ([int]$route[0].InterfaceIndex -ne [int]$source[0].InterfaceIndex) {
    throw "Windows route/source decision disagrees for $RemoteAddress"
  }
  return [PSCustomObject]@{
    DestinationPrefix = [string]$route[0].DestinationPrefix
    InterfaceIndex = [int]$route[0].InterfaceIndex
    NextHop = [string]$route[0].NextHop
    RouteMetric = [int]$route[0].RouteMetric
    source_address = [string]$source[0].IPAddress
  }
}

function Resolve-WireGuardTool {
  param([string]$Name)
  $candidates = @(
    (Join-Path (Split-Path -Parent $Binary) $Name),
    (Join-Path $env:ProgramFiles "WireGuard\$Name"),
    (Join-Path ${env:ProgramFiles(x86)} "WireGuard\$Name"),
    (Join-Path "C:\Program Files\WireGuard" $Name)
  )
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }
  $command = Get-Command $Name -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($command) {
    return $command.Source
  }
  throw "$Name is required for the physical WireGuard gate"
}

function Get-WireGuardEndpointHost {
  return ([Uri]("udp://" + $WireGuardEndpoint)).Host
}

function Get-PreferredIPv4Address {
  param([int]$InterfaceIndex)
  $addresses = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex `
    -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object {
      $_.AddressState -eq "Preferred" -and
      !$_.IPAddress.StartsWith("169.254.")
    })
  if ($addresses.Count -ne 1) {
    throw "expected one preferred IPv4 address on interface $InterfaceIndex"
  }
  return $addresses[0]
}

function Get-PhysicalDefaultRoute {
  param([int]$InterfaceIndex)
  $routes = @(Get-NetRoute -InterfaceIndex $InterfaceIndex `
    -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" `
    -PolicyStore ActiveStore -ErrorAction Stop |
    Sort-Object RouteMetric)
  if ($routes.Count -eq 0) {
    throw "physical interface $InterfaceIndex has no active default route"
  }
  return $routes[0]
}

function Get-SelectedPhysicalDefaultInterfaceIndex {
  $excluded = @(
    Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -in @($TunnelInterface, $WireGuardInterface) } |
      ForEach-Object { [int]$_.ifIndex }
  )
  $routeOutput = @(& route.exe print -4 0.0.0.0 2>$null)
  if ($LASTEXITCODE -ne 0) {
    throw "route print failed while selecting the physical underlay"
  }
  $candidates = @(
    $routeOutput | ForEach-Object {
      if (
        $_ -match
          '^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)\s*$' -and
        $Matches[1] -notmatch '^(?i:On-link)$'
      ) {
        [PSCustomObject]@{
          interface_address = [string]$Matches[2]
          metric = [int]$Matches[3]
        }
      }
    } | Sort-Object metric
  )
  foreach ($candidate in $candidates) {
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 `
      -IPAddress $candidate.interface_address -ErrorAction SilentlyContinue)
    if ($addresses.Count -ne 1) {
      continue
    }
    $interfaceIndex = [int]$addresses[0].InterfaceIndex
    if ($excluded -notcontains $interfaceIndex) {
      return $interfaceIndex
    }
  }
  throw "Windows has no selected physical IPv4 default route"
}

function Assert-WireGuardEndpointRoute {
  param([int]$ExpectedPhysicalIndex)
  $hostAddress = Get-WireGuardEndpointHost
  $routeDecision = Get-BestRoute $hostAddress
  $routes = @(Get-NetRoute -AddressFamily IPv4 `
    -DestinationPrefix "$hostAddress/32" `
    -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
  if ($routes.Count -ne 1) {
    throw "expected exactly one active WireGuard endpoint /32 route, found $($routes.Count)"
  }
  $route = $routes[0]
  $defaultRoute = Get-PhysicalDefaultRoute $ExpectedPhysicalIndex
  if (
    [int]$route.InterfaceIndex -ne $ExpectedPhysicalIndex -or
    [string]$route.NextHop -ne [string]$defaultRoute.NextHop -or
    [string]$routeDecision.DestinationPrefix -ne "$hostAddress/32" -or
    [int]$routeDecision.InterfaceIndex -ne [int]$route.InterfaceIndex -or
    [string]$routeDecision.NextHop -ne [string]$route.NextHop
  ) {
    throw "WireGuard endpoint /32 is not the actual Windows route/source decision"
  }
  return [PSCustomObject]@{
    destination_prefix = [string]$route.DestinationPrefix
    interface_index = [int]$route.InterfaceIndex
    next_hop = [string]$route.NextHop
    source_address = [string]$routeDecision.source_address
  }
}

function Get-WireGuardAdapter {
  $matches = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq $WireGuardInterface })
  if ($matches.Count -ne 1) {
    throw "expected one active WireGuard adapter named $WireGuardInterface"
  }
  return $matches[0]
}

function Assert-NativeWireGuardSecretPathAcl {
  param([string]$Path)
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  if (!$acl.AreAccessRulesProtected) {
    throw "native WireGuard secret ACL inherits permissions: $Path"
  }
  $allowed = @("S-1-5-18", "S-1-5-32-544")
  $seen = @{}
  foreach ($rule in $acl.Access) {
    $sid = $rule.IdentityReference.Translate(
      [Security.Principal.SecurityIdentifier]
    ).Value
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    if (
      $allowed -notcontains $sid -or
      $rule.AccessControlType -ne
        [Security.AccessControl.AccessControlType]::Allow -or
      ($rule.FileSystemRights -band $full) -ne $full
    ) {
      throw "unexpected native WireGuard ACL entry on ${Path}: $sid"
    }
    $seen[$sid] = $true
  }
  foreach ($sid in $allowed) {
    if (!$seen.ContainsKey($sid)) {
      throw "missing native WireGuard ACL entry $sid on $Path"
    }
  }
}

function Assert-NativeWireGuardSecretAcl {
  Read-CandidateNativeWireGuardOwnership
  foreach ($candidate in @(
    $script:CandidateNativeWireGuardConfigRootPath,
    $script:CandidateNativeWireGuardOwnerDirectoryPath,
    $script:CandidateNativeWireGuardConfigPath,
    $script:CandidateNativeWireGuardOwnerMarkerPath
  )) {
    Assert-NativeWireGuardSecretPathAcl $candidate
  }
}

function Assert-NativeNetworkRestoredBeforeRepair {
  $statePath = Join-Path $StateDir "adapter-state.json"
  $state = Get-Content -Raw -LiteralPath $statePath -ErrorAction Stop |
    ConvertFrom-Json
  $allowedPhysicalIndices = @(
    [int]$state.primary_interface_index,
    [int]$state.secondary_interface_index
  )
  $selectedPhysicalIndex = Get-SelectedPhysicalDefaultInterfaceIndex
  $route = Get-BestRoute "1.1.1.1"
  if (
    $allowedPhysicalIndices -notcontains $selectedPhysicalIndex -or
    [int]$route.InterfaceIndex -ne $selectedPhysicalIndex
  ) {
    throw "native selected physical route was not restored before repair"
  }
  if (!(Test-PublicDns)) {
    throw "native DNS was not restored before repair"
  }
  if (!(Test-ExternalHttps)) {
    throw "native HTTPS was not restored before repair"
  }
}

function Test-WireGuardHandshake {
  try {
    $wg = Resolve-WireGuardTool "wg.exe"
    $lines = @(& $wg show $WireGuardInterface latest-handshakes 2>$null)
    if ($LASTEXITCODE -ne 0) {
      return $false
    }
    foreach ($line in $lines) {
      $fields = @(([string]$line).Trim() -split "\s+")
      $timestamp = [UInt64]0
      if (
        $fields.Count -ge 2 -and
        [UInt64]::TryParse($fields[$fields.Count - 1], [ref]$timestamp) -and
        $timestamp -gt 0
      ) {
        return $true
      }
    }
  }
  catch {
    return $false
  }
  return $false
}
