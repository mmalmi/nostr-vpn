param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("Reset", "Bootstrap", "CreateAdmin", "AdminAdd", "ManualJoin", "DnsPolicy", "Verify")]
  [string]$Mode,
  [Parameter(Mandatory = $true)]
  [string]$AppExe,
  [Parameter(Mandatory = $true)]
  [string]$MarkerPath,
  [string]$StopPath = "",
  [string]$NetworkName = "Release desktop admin",
  [string]$AdminNpub = "",
  [string]$NetworkId = "",
  [string]$ParticipantNpub = "",
  [string]$ParticipantAlias = "Release Pixel",
  [string]$DataDir = "",
  [string]$CliExe = "",
  [string]$Case = "",
  [string]$DnsMode = "",
  [string]$DnsProvider = "cloudflare",
  [string]$DnsCustomUrl = "",
  [string]$DnsBootstrapIps = "",
  [string]$DnsThroughServers = "",
  [string]$AppGitSha = "",
  [string]$AppGitTree = "",
  [int]$UiTimeoutSeconds = 15,
  [int]$CoordinationTimeoutSeconds = 60,
  [int]$HoldTimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"
$Process = $null
$Evidence = [ordered]@{
  schema = 1
  mode = $Mode
  publicUiOnly = $true
  privateStateRead = $false
}

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing

function Now-Milliseconds {
  return [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
}

function Assert-ValidNpub {
  param([string]$Value, [string]$Label)
  if ($Value -notmatch '^npub1[023456789acdefghjklmnpqrstuvwxyz]{58}$') {
    throw "$Label is not a valid npub"
  }
}

function Write-Evidence {
  $Directory = Split-Path -Parent $MarkerPath
  New-Item -ItemType Directory -Force -Path $Directory | Out-Null
  $Temporary = Join-Path $Directory (
    ".{0}.{1}.{2}.tmp" -f (Split-Path -Leaf $MarkerPath), $PID, [Guid]::NewGuid().ToString("N")
  )
  try {
    $Evidence | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -Path $Temporary
    Move-Item -Force -Path $Temporary -Destination $MarkerPath
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $Temporary
  }
}

function Stop-App {
  if ($script:Process -and !$script:Process.HasExited) {
    $script:Process.CloseMainWindow() | Out-Null
    if (!$script:Process.WaitForExit(1500)) {
      Stop-Process -Id $script:Process.Id -Force -ErrorAction SilentlyContinue
      $script:Process.WaitForExit(5000) | Out-Null
    }
  }
  $script:Process = $null
}

function Stop-CanonicalAppInstances {
  Get-Process -Name "NostrVpn.Windows" -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  $Deadline = (Get-Date).AddSeconds(5)
  while (
    (Get-Date) -lt $Deadline -and
    (Get-Process -Name "NostrVpn.Windows" -ErrorAction SilentlyContinue)
  ) {
    Start-Sleep -Milliseconds 100
  }
  if (Get-Process -Name "NostrVpn.Windows" -ErrorAction SilentlyContinue) {
    throw "could not stop the canonical Windows nVPN app"
  }
}

function Start-App {
  if (!(Test-Path -LiteralPath $AppExe -PathType Leaf)) {
    throw "Windows Release app is missing: $AppExe"
  }
  if (
    $Mode -ne "DnsPolicy" -and
    ($env:NVPN_APP_DATA_DIR -or $env:NVPN_CLI_PATH)
  ) {
    throw "public-UI gate refuses NVPN_APP_DATA_DIR or NVPN_CLI_PATH overrides"
  }
  if ($Mode -eq "DnsPolicy") {
    if ([string]::IsNullOrWhiteSpace($DataDir)) {
      throw "DnsPolicy requires an isolated production data directory"
    }
    $env:NVPN_APP_DATA_DIR = $DataDir
    Remove-Item Env:NVPN_CLI_PATH -ErrorAction SilentlyContinue
  }
  Stop-CanonicalAppInstances
  $LogDirectory = Split-Path -Parent $MarkerPath
  New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
  $LogBase = Join-Path $LogDirectory ("windows-{0}-app" -f $Mode.ToLowerInvariant())
  $script:Process = Start-Process `
    -FilePath $AppExe `
    -WorkingDirectory (Split-Path -Parent $AppExe) `
    -RedirectStandardOutput "$LogBase.log" `
    -RedirectStandardError "$LogBase.err.log" `
    -PassThru
}

function Find-Control {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationId,
    [int]$TimeoutSeconds = $UiTimeoutSeconds
  )
  $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $Deadline) {
    $script:Process.Refresh()
    if ($script:Process.HasExited) {
      throw "Windows app exited while waiting for $AutomationId"
    }
    if ($script:Process.MainWindowHandle -ne [IntPtr]::Zero) {
      $Window = [System.Windows.Automation.AutomationElement]::FromHandle(
        $script:Process.MainWindowHandle
      )
      $Condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        $AutomationId
      )
      $Matches = $Window.FindAll(
        [System.Windows.Automation.TreeScope]::Descendants,
        $Condition
      )
      foreach ($Element in $Matches) {
        if (!$Element.Current.IsOffscreen) {
          return $Element
        }
        try {
          $ScrollItem = $Element.GetCurrentPattern(
            [System.Windows.Automation.ScrollItemPattern]::Pattern
          )
          $ScrollItem.ScrollIntoView()
          Start-Sleep -Milliseconds 150
          if (!$Element.Current.IsOffscreen) {
            return $Element
          }
        }
        catch {
          continue
        }
      }
    }
    Start-Sleep -Milliseconds 100
  }
  throw "visible Windows UI Automation control did not appear: $AutomationId"
}

function Test-VisibleControlName {
  param(
    [Parameter(Mandatory = $true)]
    [System.Windows.Automation.AutomationElement]$Window,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  $Condition = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::NameProperty,
    $Name
  )
  $Matches = $Window.FindAll(
    [System.Windows.Automation.TreeScope]::Descendants,
    $Condition
  )
  foreach ($Element in $Matches) {
    if (!$Element.Current.IsOffscreen) { return $true }
  }
  return $false
}

function Invoke-Control {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationId
  )
  $Element = Find-Control $AutomationId
  $Pattern = $Element.GetCurrentPattern(
    [System.Windows.Automation.InvokePattern]::Pattern
  )
  $Pattern.Invoke()
  Start-Sleep -Milliseconds 200
}

function Expand-Control {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationId
  )
  $Element = Find-Control $AutomationId
  $Pattern = $Element.GetCurrentPattern(
    [System.Windows.Automation.ExpandCollapsePattern]::Pattern
  )
  if (
    $Pattern.Current.ExpandCollapseState -ne
    [System.Windows.Automation.ExpandCollapseState]::Expanded
  ) {
    $Pattern.Expand()
  }
  Start-Sleep -Milliseconds 200
}

function Set-ControlValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationId,
    [Parameter(Mandatory = $true)]
    [string]$Value
  )
  $Element = Find-Control $AutomationId
  $Pattern = $Element.GetCurrentPattern(
    [System.Windows.Automation.ValuePattern]::Pattern
  )
  $Pattern.SetValue($Value)
  Start-Sleep -Milliseconds 150
  if ($Pattern.Current.Value -ne $Value) {
    throw "Windows UI Automation did not retain $AutomationId"
  }
}

function Select-ComboItem {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationId,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  $Combo = Find-Control $AutomationId
  $Expand = $Combo.GetCurrentPattern(
    [System.Windows.Automation.ExpandCollapsePattern]::Pattern
  )
  $Expand.Expand()
  Start-Sleep -Milliseconds 150
  $Container = $Combo.GetCurrentPattern(
    [System.Windows.Automation.ItemContainerPattern]::Pattern
  )
  $Item = $Container.FindItemByProperty(
    $null,
    [System.Windows.Automation.AutomationElement]::NameProperty,
    $Name
  )
  if ($null -eq $Item) {
    throw "Windows UI Automation could not select $Name in $AutomationId"
  }
  $Pattern = $Item.GetCurrentPattern(
    [System.Windows.Automation.SelectionItemPattern]::Pattern
  )
  $Pattern.Select()
  Start-Sleep -Milliseconds 200
  if ((Read-ComboItem $AutomationId) -ne $Name) {
    throw "Windows UI Automation did not retain $Name in $AutomationId"
  }
}

function Read-ComboItem {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationId
  )
  $Combo = Find-Control $AutomationId
  $Pattern = $Combo.GetCurrentPattern(
    [System.Windows.Automation.SelectionPattern]::Pattern
  )
  $Selection = @($Pattern.Current.GetSelection())
  if ($Selection.Count -ne 1) {
    throw "Windows UI Automation found no exact selection in $AutomationId"
  }
  return $Selection[0].Current.Name
}

function Read-ControlValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationId
  )
  $Element = Find-Control $AutomationId
  $Pattern = $Element.GetCurrentPattern(
    [System.Windows.Automation.ValuePattern]::Pattern
  )
  return $Pattern.Current.Value
}

function ConvertTo-CanonicalIpCsv {
  param(
    [AllowEmptyString()]
    [string]$Value
  )
  $Canonical = @(
    ($Value -split '[,\s]+') |
      ForEach-Object { $_.Trim() } |
      Where-Object { ![string]::IsNullOrWhiteSpace($_) } |
      ForEach-Object {
        [System.Net.IPAddress]$Parsed = $null
        if (![System.Net.IPAddress]::TryParse($_, [ref]$Parsed)) {
          throw "Windows DNS UI returned an invalid IP address: $_"
        }
        $Parsed.ToString().ToLowerInvariant()
      } |
      Sort-Object -Unique
  )
  return [string]::Join(",", [string[]]$Canonical)
}

function Read-PublicText {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AutomationId
  )
  $Element = Find-Control $AutomationId
  $Value = $Element.Current.Name.Trim()
  if ([string]::IsNullOrWhiteSpace($Value)) {
    throw "Windows public UI value is empty: $AutomationId"
  }
  return $Value
}

function Save-WindowScreenshot {
  param([string]$Label)
  $script:Process.Refresh()
  if ($script:Process.MainWindowHandle -eq [IntPtr]::Zero) {
    throw "Windows app has no visible window for screenshot"
  }
  $Window = [System.Windows.Automation.AutomationElement]::FromHandle(
    $script:Process.MainWindowHandle
  )
  $Bounds = $Window.Current.BoundingRectangle
  $Width = [Math]::Max(1, [int][Math]::Ceiling($Bounds.Width))
  $Height = [Math]::Max(1, [int][Math]::Ceiling($Bounds.Height))
  $Bitmap = New-Object System.Drawing.Bitmap $Width, $Height
  $Graphics = [System.Drawing.Graphics]::FromImage($Bitmap)
  $Path = Join-Path (Split-Path -Parent $MarkerPath) "$Label.png"
  try {
    $Graphics.CopyFromScreen(
      [int]$Bounds.Left,
      [int]$Bounds.Top,
      0,
      0,
      $Bitmap.Size
    )
    $Bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
  } finally {
    $Graphics.Dispose()
    $Bitmap.Dispose()
  }
}

function Wait-ForStopRequest {
  if ([string]::IsNullOrWhiteSpace($StopPath)) {
    throw "AdminAdd requires a stop path"
  }
  $Deadline = (Get-Date).AddSeconds($HoldTimeoutSeconds)
  while ((Get-Date) -lt $Deadline) {
    if (Test-Path -LiteralPath $StopPath -PathType Leaf) {
      return
    }
    $script:Process.Refresh()
    if ($script:Process.HasExited) {
      throw "Windows app exited while holding accepted roster delivery"
    }
    Start-Sleep -Milliseconds 100
  }
  throw "Windows admin app hold timed out before the orchestrator released it"
}

try {
  if ($Mode -eq "Reset") {
    if ($env:NVPN_APP_DATA_DIR -or $env:NVPN_CLI_PATH) {
      throw "public-UI gate refuses NVPN_APP_DATA_DIR or NVPN_CLI_PATH overrides"
    }
    Stop-CanonicalAppInstances
    $AppData = [Environment]::GetFolderPath(
      [Environment+SpecialFolder]::ApplicationData
    )
    $DataDirectory = Join-Path $AppData "Nostr VPN"
    if ((Split-Path -Parent $DataDirectory) -ne $AppData) {
      throw "refusing an unsafe canonical Windows app-data path"
    }
    Remove-Item -LiteralPath $DataDirectory -Recurse -Force -ErrorAction SilentlyContinue
    $Evidence.resetComplete = $true
    $Evidence.canonicalProfile = $true
    Write-Evidence
    exit 0
  }

  Start-App
  switch ($Mode) {
    "Bootstrap" {
      $null = Find-Control "ManualJoinCreateNetworkChoice"
      Invoke-Control "ManualJoinChooseJoin"
      Expand-Control "ManualJoinExpander"
      $Joiner = Read-PublicText "ManualJoinJoinerDeviceIdValue"
      Assert-ValidNpub $Joiner "Windows joiner Device ID"
      $Evidence.joinerNpub = $Joiner
      $Evidence.bootstrapComplete = $true
    }
    "CreateAdmin" {
      Invoke-Control "ManualJoinCreateNetworkChoice"
      Set-ControlValue "ManualJoinCreateNetworkName" $NetworkName
      Invoke-Control "ManualJoinCreateNetworkSubmit"
      Invoke-Control "ManualJoinAdminOpen"
      $Admin = Read-PublicText "ManualJoinAdminDeviceIdValue"
      Assert-ValidNpub $Admin "Windows admin Device ID"
      $Mesh = (
        Read-PublicText "ManualJoinAdminNetworkIdValue"
      ) -replace '[\s-]', ''
      if ([string]::IsNullOrWhiteSpace($Mesh)) {
        throw "Windows public Network ID is empty"
      }
      $Evidence.adminNpub = $Admin
      $Evidence.networkId = $Mesh
      $Evidence.adminReady = $true
      Save-WindowScreenshot "create-admin"
    }
    "AdminAdd" {
      Assert-ValidNpub $ParticipantNpub "Pixel joiner Device ID"
      Invoke-Control "ManualJoinAdminOpen"
      Set-ControlValue "ManualJoinAdminDeviceId" $ParticipantNpub
      Set-ControlValue "ManualJoinAdminDeviceName" $ParticipantAlias
      $Evidence.participantNpub = $ParticipantNpub
      $Evidence.approvalSubmittedMs = Now-Milliseconds
      Invoke-Control "ManualJoinAdminSubmit"
      Write-Evidence
      $null = Find-Control `
        "RosterParticipantAccepted-$ParticipantNpub" `
        $CoordinationTimeoutSeconds
      $Evidence.acceptedSelector = "exact accepted roster participant row"
      $Evidence.desktopAccepted = $true
      $Evidence.acceptedAtMs = Now-Milliseconds
      Save-WindowScreenshot "desktop-admin-accepted"
      Write-Evidence
      Wait-ForStopRequest
      $Evidence.holdReleased = $true
    }
    "ManualJoin" {
      Assert-ValidNpub $AdminNpub "Pixel admin Device ID"
      if ([string]::IsNullOrWhiteSpace($NetworkId)) {
        throw "Pixel admin Network ID is empty"
      }
      Invoke-Control "ManualJoinChooseJoin"
      Expand-Control "ManualJoinExpander"
      $Joiner = Read-PublicText "ManualJoinJoinerDeviceIdValue"
      Assert-ValidNpub $Joiner "Windows joiner Device ID"
      $Evidence.joinerNpub = $Joiner
      $Evidence.adminNpub = $AdminNpub
      $Evidence.networkId = $NetworkId
      Write-Evidence
      Set-ControlValue "ManualJoinAdminId" $AdminNpub
      Set-ControlValue "ManualJoinNetworkId" $NetworkId
      $Evidence.manualSubmittedMs = Now-Milliseconds
      Invoke-Control "ManualJoinSubmit"
      Write-Evidence
      $null = Find-Control `
        "RosterParticipantAccepted-$AdminNpub" `
        $CoordinationTimeoutSeconds
      $Evidence.acceptedSelector = "exact accepted roster participant row"
      $Evidence.desktopAccepted = $true
      $Evidence.acceptedAtMs = Now-Milliseconds
      Save-WindowScreenshot "desktop-joiner-accepted"
    }
    "DnsPolicy" {
      $Cases = @(
        "automatic",
        "cloudflare",
        "quad9",
        "custom",
        "through-exit"
      )
      $ModeLabels = @{
        automatic = "Automatic (recommended)"
        encrypted = "Encrypted DNS"
        through_exit = "DNS through exit"
      }
      $ProviderLabels = @{
        cloudflare = "Cloudflare"
        quad9 = "Quad9"
        custom = "Custom DoH"
      }
      if (
        $Case -notin $Cases -or
        !$ModeLabels.ContainsKey($DnsMode) -or
        !$ProviderLabels.ContainsKey($DnsProvider)
      ) {
        throw "DnsPolicy received an unsupported policy"
      }
      if (
        !(Test-Path -LiteralPath $CliExe -PathType Leaf) -or
        $AppGitSha -notmatch '^[0-9a-f]{40}$' -or
        $AppGitTree -notmatch '^[0-9a-f]{40}$'
      ) {
        throw "DnsPolicy exact artifact identity is incomplete"
      }
      Invoke-Control "ManualJoinCreateNetworkChoice"
      Set-ControlValue "ManualJoinCreateNetworkName" "Release DNS $Case"
      Invoke-Control "ManualJoinCreateNetworkSubmit"
      $null = Find-Control "ManualJoinAdminOpen"
      Invoke-Control "ExitDnsInternetNavigation"
      if ((Read-PublicText "InternetSourceStatus") -notmatch "Direct") {
        throw "Windows Internet page did not identify the current Direct source"
      }
      Select-ComboItem "ExitDnsMode" $ModeLabels[$DnsMode]
      if ($DnsMode -eq "encrypted") {
        Select-ComboItem "ExitDnsProvider" $ProviderLabels[$DnsProvider]
        if ($DnsProvider -eq "custom") {
          Set-ControlValue "ExitDnsCustomUrl" $DnsCustomUrl
          Set-ControlValue "ExitDnsBootstrapIps" $DnsBootstrapIps
        }
      }
      elseif ($DnsMode -eq "through_exit") {
        Set-ControlValue "ExitDnsThroughServers" $DnsThroughServers
      }
      Invoke-Control "ExitDnsSave"
      Start-Sleep -Milliseconds 750
      Save-WindowScreenshot "dns-$Case-saved"
      Stop-App
      Start-App
      Invoke-Control "ExitDnsInternetNavigation"
      if ((Read-PublicText "InternetSourceStatus") -notmatch "Direct") {
        throw "Windows relaunch lost the current Direct source status"
      }
      if ((Read-ComboItem "ExitDnsMode") -ne $ModeLabels[$DnsMode]) {
        throw "Windows relaunch changed the saved DNS mode"
      }
      if ($DnsMode -eq "encrypted") {
        if (
          (Read-ComboItem "ExitDnsProvider") -ne
          $ProviderLabels[$DnsProvider]
        ) {
          throw "Windows relaunch changed the saved DNS provider"
        }
        if (
          $DnsProvider -eq "custom" -and
          (
            (Read-ControlValue "ExitDnsCustomUrl") -ne $DnsCustomUrl -or
            (
              ConvertTo-CanonicalIpCsv (
                Read-ControlValue "ExitDnsBootstrapIps"
              )
            ) -ne (ConvertTo-CanonicalIpCsv $DnsBootstrapIps)
          )
        ) {
          throw "Windows relaunch changed the custom DoH fields"
        }
      }
      elseif (
        $DnsMode -eq "through_exit" -and
        (Read-ControlValue "ExitDnsThroughServers") -ne $DnsThroughServers
      ) {
        throw "Windows relaunch changed the through-exit DNS field"
      }
      Save-WindowScreenshot "dns-$Case-readback"
      $Evidence.receiptSchema = 1
      $Evidence.platform = "windows"
      $Evidence.case = $Case
      $Evidence.evidenceSource = "shipped-ui-restart-readback"
      $Evidence.savedViaShippedUi = $true
      $Evidence.uiRestartReadback = $true
      $Evidence.releaseBlackbox = $true
      $Evidence.exitDnsMode = $DnsMode
      $Evidence.exitDnsDohProvider = $DnsProvider
      $Evidence.exitDnsCustomDohUrl = $DnsCustomUrl
      $Evidence.exitDnsCustomDohBootstrapIps = $DnsBootstrapIps
      $Evidence.exitDnsThroughExitServers = $DnsThroughServers
      $Evidence.appGitSha = $AppGitSha
      $Evidence.appGitTree = $AppGitTree
      $Evidence.appExecutableSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $AppExe
      ).Hash.ToLowerInvariant()
      $Evidence.cliExecutableSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $CliExe
      ).Hash.ToLowerInvariant()
      $Evidence.productionDataDirOverride = $true
    }
    "Verify" {
      Assert-ValidNpub $ParticipantNpub "expected accepted participant"
      $null = Find-Control `
        "RosterParticipantAccepted-$ParticipantNpub" `
        $UiTimeoutSeconds
      $Evidence.participantNpub = $ParticipantNpub
      $Evidence.acceptedSelector = "exact accepted roster participant row"
      $Evidence.relaunchAccepted = $true
      Save-WindowScreenshot "relaunch-accepted"
    }
  }
  Write-Evidence
} finally {
  Stop-App
  if ($Mode -eq "DnsPolicy") {
    Remove-Item Env:NVPN_APP_DATA_DIR -ErrorAction SilentlyContinue
    Remove-Item Env:NVPN_CLI_PATH -ErrorAction SilentlyContinue
  }
}
