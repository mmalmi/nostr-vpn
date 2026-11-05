$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
  (Join-Path $PSScriptRoot 'windows-release-mobile-join-remote.ps1'),
  [ref]$tokens, [ref]$errors
)
if ($errors) { throw ($errors | Out-String) }
foreach ($name in @('Normalize-ComparableWindowsPath', 'Get-ServiceCommandExecutable', 'Test-OwnedServiceConfig')) {
  $function = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq $name
  }, $false)
  if (!$function) { throw "Missing ownership function: $name" }
  . ([ScriptBlock]::Create($function.Extent.Text))
}
$config = 'C:\Users\release-test\AppData\Roaming\Nostr VPN\config.toml'
$prefix = '"C:\candidate\nvpn.exe" daemon --service --config "'
$suffix = '" --iface "nvpn" --mesh-refresh-interval-secs 60'
$cases = @(
  @{ command = $prefix + $config + $suffix; expected = $true },
  @{ command = $prefix + '\\?\' + $config + $suffix; expected = $true },
  @{ command = $prefix + $config.ToUpperInvariant() + $suffix; expected = $true },
  @{ command = $prefix + $config.Replace('release-test', 'other-user') + $suffix; expected = $false },
  @{ command = $prefix + $config + '.extra' + $suffix; expected = $false },
  @{ command = $prefix + $config + $suffix + ' --other'; expected = $false },
  @{ command = 'unrelated-service --config "' + $config + '"'; expected = $false },
  @{ command = 'C:\candidate\nvpn.exe daemon --service --config "' + $config + '" --iface nvpn --mesh-refresh-interval-secs 60'; expected = $true },
  @{ command = '\\?\C:\candidate\nvpn.exe daemon --service --config "\\?\' + $config + '" --iface nvpn --mesh-refresh-interval-secs 60'; expected = $true },
  @{ command = '"C:\candidate with spaces\nvpn.exe" daemon --service --config "' + $config + '" --iface nvpn --mesh-refresh-interval-secs 60'; expected = $true },
  @{ command = 'C:\candidate with spaces\nvpn.exe daemon --service --config "' + $config + '" --iface nvpn --mesh-refresh-interval-secs 60'; expected = $false },
  @{ command = $prefix + $config + '" --iface unrelated --mesh-refresh-interval-secs 60'; expected = $false },
  @{ command = 'C:\candidate\nvpn.exe daemon --service --config "' + $config + '.extra" --iface nvpn --mesh-refresh-interval-secs 60'; expected = $false },
  @{ command = 'C:\candidate\nvpn.exe daemon --service --config "' + $config + '" --iface nvpn --mesh-refresh-interval-secs 60 --other'; expected = $false }
)
foreach ($case in $cases) {
  if ((Test-OwnedServiceConfig $case.command $config) -ne $case.expected) {
    throw "Service config ownership mismatch: $($case | ConvertTo-Json -Compress)"
  }
}
# Config ownership does not replace the separate candidate binary hash check.
foreach ($case in @(
  @{command='C:\candidate\nvpn.exe daemon --service'; executable='C:\candidate\nvpn.exe'},
  @{command='"C:\candidate with spaces\nvpn.exe" daemon --service'; executable='C:\candidate with spaces\nvpn.exe'},
  @{command='\\?\C:\candidate\nvpn.exe daemon --service'; executable='\\?\C:\candidate\nvpn.exe'},
  @{command='"unterminated daemon --service'; executable=$null}
)) {
  if ((Get-ServiceCommandExecutable $case.command) -ne $case.executable) {
    throw 'Service executable parsing differs from Windows command quoting'
  }
}
Write-Output 'WINDOWS_SERVICE_CONFIG_OWNERSHIP_OK configCases=14 executableCases=4'
