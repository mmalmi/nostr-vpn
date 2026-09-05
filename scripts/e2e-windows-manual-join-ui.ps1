param(
  [string]$AppExe,
  [string]$ArtifactRoot,
  [int]$TimeoutSeconds = 20
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
if (!$ArtifactRoot) {
  $ArtifactRoot = Join-Path $Root "artifacts\windows-manual-join-ui"
}
if (!$AppExe) {
  $AppExe = Join-Path $Root "windows\NostrVpn.Windows\bin\Release\net8.0-windows\NostrVpn.Windows.exe"
}
$AdminDataDir = Join-Path $ArtifactRoot "admin"
$JoinerDataDir = Join-Path $ArtifactRoot "joiner"
$Result = Join-Path $ArtifactRoot "result.json"
$AppLog = Join-Path $ArtifactRoot "app.log"
$Process = $null

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NvpnManualJoinInput {
  [DllImport("user32.dll")]
  public static extern bool SetForegroundWindow(IntPtr handle);
  [DllImport("kernel32.dll")]
  public static extern uint SetThreadExecutionState(uint flags);
}
'@

function Stop-IsolatedProcesses {
  if ($script:Process -and !$script:Process.HasExited) {
    Stop-Process -Id $script:Process.Id -Force -ErrorAction SilentlyContinue
    $script:Process.WaitForExit(5000) | Out-Null
  }
  $script:Process = $null
  Get-CimInstance Win32_Process -Filter "Name = 'nvpn.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine.Contains($ArtifactRoot) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Find-Control {
  param([string]$AutomationId)
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
      }
    }
    Start-Sleep -Milliseconds 100
  }
  throw "visible Windows UI Automation control did not appear: $AutomationId"
}

function Invoke-Control {
  param([string]$AutomationId)
  $Element = Find-Control $AutomationId
  $Pattern = $Element.GetCurrentPattern(
    [System.Windows.Automation.InvokePattern]::Pattern
  )
  $Pattern.Invoke()
  Start-Sleep -Milliseconds 250
}

function Expand-Control {
  param([string]$AutomationId)
  $Element = Find-Control $AutomationId
  $Pattern = $Element.GetCurrentPattern(
    [System.Windows.Automation.ExpandCollapsePattern]::Pattern
  )
  if ($Pattern.Current.ExpandCollapseState -ne
      [System.Windows.Automation.ExpandCollapseState]::Expanded) {
    $Pattern.Expand()
  }
  Start-Sleep -Milliseconds 250
}

function Set-ControlValue {
  param([string]$AutomationId, [string]$Value)
  $Element = Find-Control $AutomationId
  $Pattern = $Element.GetCurrentPattern(
    [System.Windows.Automation.ValuePattern]::Pattern
  )
  $Pattern.SetValue($Value)
  Start-Sleep -Milliseconds 200
  if ($Pattern.Current.Value -ne $Value) {
    throw "Windows UI Automation did not retain $AutomationId"
  }
}

function Start-IsolatedApp {
  param([string]$DataDir)
  $env:NVPN_APP_DATA_DIR = $DataDir
  $env:NVPN_CLI_PATH = $Nvpn
  $Dotnet = Get-Command dotnet -ErrorAction Stop
  $env:DOTNET_ROOT = Split-Path -Parent $Dotnet.Source
  $script:Process = Start-Process -FilePath $AppExe -PassThru `
    -RedirectStandardOutput $AppLog -RedirectStandardError "$AppLog.err"
  $null = Find-Control $(if ($DataDir -eq $JoinerDataDir) {
    "ManualJoinChooseJoin"
  } else {
    "ManualJoinAdminOpen"
  })
}

function Wait-Fixture {
  param([string]$Command, [string]$Label)
  $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $Deadline) {
    $PreviousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
      & $Fixture $Command `
        --admin-data-dir $AdminDataDir `
        --joiner-data-dir $JoinerDataDir `
        --result $Result 2>$null
      $VerifyExitCode = $LASTEXITCODE
    } finally {
      $ErrorActionPreference = $PreviousErrorActionPreference
    }
    if ($VerifyExitCode -eq 0) { return }
    $script:Process.Refresh()
    if ($script:Process.HasExited) {
      throw "Windows app exited before persisting the $Label action"
    }
    Start-Sleep -Milliseconds 100
  }
  & $Fixture $Command `
    --admin-data-dir $AdminDataDir `
    --joiner-data-dir $JoinerDataDir `
    --result $Result
  throw "Windows UI did not persist the $Label action within $TimeoutSeconds seconds"
}

function Save-Screenshot {
  param([string]$Name)
  $Bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $script:Process.Refresh()
  [NvpnManualJoinInput]::SetForegroundWindow($script:Process.MainWindowHandle) |
    Out-Null
  Start-Sleep -Milliseconds 250
  $Window = [System.Windows.Automation.AutomationElement]::FromHandle(
    $script:Process.MainWindowHandle
  )
  $WindowBounds = $Window.Current.BoundingRectangle
  $SampleX = [Math]::Min(
    $Bounds.Width - 1,
    [Math]::Max(0, [int]($WindowBounds.Left - $Bounds.Left + 50))
  )
  $SampleY = [Math]::Min(
    $Bounds.Height - 1,
    [Math]::Max(0, [int]($WindowBounds.Top - $Bounds.Top + 100))
  )
  $ScreenshotError = $null
  for ($ScreenshotAttempt = 1; $ScreenshotAttempt -le 20; $ScreenshotAttempt++) {
    $Bitmap = New-Object System.Drawing.Bitmap $Bounds.Width, $Bounds.Height
    $Graphics = [System.Drawing.Graphics]::FromImage($Bitmap)
    try {
      $Graphics.CopyFromScreen(
        $Bounds.Location,
        [System.Drawing.Point]::Empty,
        $Bounds.Size
      )
      $PaintSample = $Bitmap.GetPixel($SampleX, $SampleY)
      if (
        $PaintSample.R -ge 250 -and
        $PaintSample.G -ge 250 -and
        $PaintSample.B -ge 250
      ) {
        throw "the visible WPF content has not painted yet"
      }
      $Bitmap.Save(
        (Join-Path $ArtifactRoot "$Name.png"),
        [System.Drawing.Imaging.ImageFormat]::Png
      )
      return
    } catch {
      $ScreenshotError = $_
      if ($ScreenshotAttempt -lt 20) {
        Start-Sleep -Milliseconds 250
      }
    } finally {
      $Graphics.Dispose()
      $Bitmap.Dispose()
    }
  }
  throw (
    "could not capture the painted visible WPF window after 20 attempts: {0}" -f
    $ScreenshotError
  )
}

try {
  if ([NvpnManualJoinInput]::SetThreadExecutionState(2147483651) -eq 0) {
    throw "could not hold the interactive display for visible UI evidence"
  }
  Set-Location $Root
  New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $AdminDataDir, $JoinerDataDir
  Remove-Item -Force -ErrorAction SilentlyContinue $Result, $AppLog, "$AppLog.err"

  $CargoTarget = (& cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json).target_directory
  if ($LASTEXITCODE -ne 0) { throw "desktop manual-join fixture metadata failed" }
  $Fixture = Join-Path $CargoTarget "release\examples\desktop_manual_join_e2e_fixture.exe"
  if (!(Test-Path -LiteralPath $Fixture -PathType Leaf)) {
    throw "desktop manual-join fixture must be prepared before the UI task starts"
  }
  & $Fixture prepare `
    --admin-data-dir $AdminDataDir `
    --joiner-data-dir $JoinerDataDir `
    --result $Result
  if ($LASTEXITCODE -ne 0) { throw "desktop manual-join fixture preparation failed" }

  if (!(Test-Path $AppExe)) { throw "Windows release app not found: $AppExe" }
  $Nvpn = Join-Path (Split-Path -Parent $AppExe) "nvpn.exe"
  if (!(Test-Path $Nvpn)) { throw "Windows release app has no bundled nvpn.exe: $AppExe" }
  Get-Process -Name NostrVpn.Windows -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

  $Metadata = Get-Content -Raw $Result | ConvertFrom-Json
  Start-IsolatedApp $JoinerDataDir
  Invoke-Control "ManualJoinChooseJoin"
  Expand-Control "ManualJoinExpander"
  Set-ControlValue "ManualJoinAdminId" $Metadata.adminNpub
  Set-ControlValue "ManualJoinNetworkId" $Metadata.meshNetworkId
  Invoke-Control "ManualJoinSubmit"
  Wait-Fixture "verify-joiner" "joiner manual-join"
  Save-Screenshot "joiner"
  Stop-IsolatedProcesses

  Start-IsolatedApp $AdminDataDir
  Invoke-Control "ManualJoinAdminOpen"
  Set-ControlValue "ManualJoinAdminDeviceId" $Metadata.joinerNpub
  Set-ControlValue "ManualJoinAdminDeviceName" $Metadata.joinerAlias
  Invoke-Control "ManualJoinAdminSubmit"
  Wait-Fixture "verify-admin" "admin add-device"
  Save-Screenshot "admin"
  & $Fixture capture-delivery `
    --admin-data-dir $AdminDataDir `
    --joiner-data-dir $JoinerDataDir `
    --result $Result
  if ($LASTEXITCODE -ne 0) {
    throw "desktop manual-join UI did not queue the exact signed roster"
  }

  Write-Host "WINDOWS_DESKTOP_MANUAL_JOIN_UI_ACTIONS_OK"
  Write-Host "Result: $Result"
} finally {
  [NvpnManualJoinInput]::SetThreadExecutionState(2147483648) | Out-Null
  Stop-IsolatedProcesses
  Remove-Item Env:NVPN_APP_DATA_DIR -ErrorAction SilentlyContinue
  Remove-Item Env:NVPN_CLI_PATH -ErrorAction SilentlyContinue
}
