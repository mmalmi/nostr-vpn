param(
  [Parameter(Mandatory = $true)]
  [string]$ScriptPath,
  [int]$TimeoutSeconds = 180,
  [switch]$CleanupConsentPrompt
)

$ErrorActionPreference = "Stop"
$ScriptPath = (Resolve-Path $ScriptPath).Path
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$ArtifactRoot = Join-Path $Root "artifacts\windows-interactive-e2e"
$TaskName = "NvpnInteractiveE2E-$([Guid]::NewGuid().ToString('N'))"
$RunnerPath = Join-Path $ArtifactRoot "$TaskName.ps1"
$ResultPath = Join-Path $ArtifactRoot "$TaskName.exit"
$LogPath = Join-Path $ArtifactRoot "$TaskName.log"
$InteractiveUser = (Get-CimInstance Win32_ComputerSystem).UserName

if ([string]::IsNullOrWhiteSpace($InteractiveUser)) {
  throw "no interactively logged-in Windows user is available for the GUI e2e"
}

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
$QuotedScript = $ScriptPath.Replace("'", "''")
$QuotedResult = $ResultPath.Replace("'", "''")
$QuotedLog = $LogPath.Replace("'", "''")
@"
`$ErrorActionPreference = 'Continue'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$QuotedScript' *> '$QuotedLog'
`$ExitCode = if (`$LASTEXITCODE -is [int]) { `$LASTEXITCODE } else { 1 }
Set-Content -Path '$QuotedResult' -Value `$ExitCode
exit `$ExitCode
"@ | Set-Content -Path $RunnerPath -Encoding utf8

$Action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$RunnerPath`""
$Principal = New-ScheduledTaskPrincipal `
  -UserId $InteractiveUser `
  -LogonType Interactive `
  -RunLevel Limited

try {
  Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Principal $Principal `
    -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName

  $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $Deadline -and !(Test-Path $ResultPath)) {
    Start-Sleep -Milliseconds 250
  }
  if (!(Test-Path $ResultPath)) {
    throw "interactive Windows GUI e2e timed out after $TimeoutSeconds seconds"
  }

  if (Test-Path $LogPath) {
    Get-Content $LogPath
  }
  $ExitCode = [int](Get-Content -Raw $ResultPath).Trim()
  if ($ExitCode -ne 0) {
    throw "interactive Windows GUI e2e failed with exit code $ExitCode"
  }
} finally {
  # Task Scheduler stops its launcher but can leave the nested test alive.
  Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
    Where-Object { $_.CommandLine -and $_.CommandLine.Contains($RunnerPath) } |
    ForEach-Object { & taskkill.exe /PID $_.ProcessId /T /F | Out-Null }
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($CleanupConsentPrompt) {
    Get-Process consent -ErrorAction SilentlyContinue |
      Stop-Process -Force -ErrorAction SilentlyContinue
  }
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Remove-Item -Force $RunnerPath, $ResultPath -ErrorAction SilentlyContinue
}
