$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'windows-installer-migrate.ps1')

function Assert-True([bool] $Condition, [string] $Message) {
    if (!$Condition) { throw $Message }
}

function Assert-Throws([scriptblock] $Action, [string] $Message) {
    try {
        & $Action
    } catch {
        return
    }
    throw $Message
}

$root = Join-Path ([IO.Path]::GetTempPath()) ("nvpn-installer-test-" + [guid]::NewGuid())
try {
    $legacyDir = Join-Path $root 'Program Files\Nostr VPN'
    $currentDir = Join-Path $root 'LocalAppData\Programs\Nostr VPN'
    $configDir = Join-Path $root 'Roaming\Nostr VPN'
    New-Item -ItemType Directory -Force -Path $legacyDir, $currentDir, $configDir | Out-Null
    Set-Content -LiteralPath (Join-Path $legacyDir 'uninstall.exe') -Value legacy
    Set-Content -LiteralPath (Join-Path $legacyDir 'nostr-vpn-gui.exe') -Value legacy
    Set-Content -LiteralPath (Join-Path $currentDir 'unins000.exe') -Value current
    Set-Content -LiteralPath (Join-Path $currentDir 'NostrVpn.Windows.exe') -Value current
    $config = Join-Path $configDir 'config.toml'
    Set-Content -LiteralPath $config -Value 'preserve=true'
    $configHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $config).Hash

    $legacy = Resolve-NvpnOwnedRegistration -Kind legacy -RegistryPath 'legacy-key' -Values ([pscustomobject]@{
        DisplayName = 'Nostr VPN'
        InstallLocation = $legacyDir
        UninstallString = '"' + (Join-Path $legacyDir 'uninstall.exe') + '"'
        MainBinaryName = 'nostr-vpn-gui.exe'
    })
    $current = Resolve-NvpnOwnedRegistration -Kind current -RegistryPath 'current-key' -Values ([pscustomobject]@{
        DisplayName = 'Nostr VPN version 4.1.5'
        InstallLocation = $currentDir
        UninstallString = '"' + (Join-Path $currentDir 'unins000.exe') + '" /SILENT'
    })
    Assert-True $legacy.RequiresElevation 'Legacy per-machine migration did not require elevation.'
    Assert-True (!$current.RequiresElevation) 'Current per-user migration unexpectedly required elevation.'

    $registered = @{ 'legacy-key' = $true; 'current-key' = $true }
    $start = {
        param($Item)
        Remove-Item -Force -LiteralPath $Item.MainExecutable, $Item.Uninstaller
        $registered[$Item.RegistryPath] = $false
        return 0
    }.GetNewClosure()
    $registrationExists = {
        param($Item)
        return $registered[$Item.RegistryPath]
    }.GetNewClosure()
    Invoke-NvpnOwnedUninstall $legacy -StartUninstaller $start -RegistrationExists $registrationExists
    Invoke-NvpnOwnedUninstall $current -StartUninstaller $start -RegistrationExists $registrationExists
    Assert-True ((Get-FileHash -Algorithm SHA256 -LiteralPath $config).Hash -eq $configHash) 'Migration changed roaming config data.'

    $outside = Join-Path $root 'outside.exe'
    Set-Content -LiteralPath $outside -Value outside
    Assert-Throws {
        Resolve-NvpnOwnedRegistration -Kind legacy -RegistryPath 'bad-key' -Values ([pscustomobject]@{
            DisplayName = 'Nostr VPN'
            InstallLocation = $legacyDir
            UninstallString = '"' + $outside + '"'
            MainBinaryName = 'nostr-vpn-gui.exe'
        })
    } 'An outside legacy uninstaller was accepted.'

    Assert-Throws {
        Resolve-NvpnOwnedRegistration -Kind current -RegistryPath 'bad-current-key' -Values ([pscustomobject]@{
            DisplayName = 'Other VPN version 4.1.5'
            InstallLocation = $currentDir
            UninstallString = '"' + (Join-Path $currentDir 'unins000.exe') + '"'
        })
    } 'An unowned current installer registration was accepted.'

    New-Item -ItemType File -Force -Path (Join-Path $currentDir 'unins000.exe'), (Join-Path $currentDir 'NostrVpn.Windows.exe') | Out-Null
    $current = Resolve-NvpnOwnedRegistration -Kind current -RegistryPath 'failed-key' -Values ([pscustomobject]@{
        DisplayName = 'Nostr VPN version 4.1.5'
        InstallLocation = $currentDir
        UninstallString = '"' + (Join-Path $currentDir 'unins000.exe') + '"'
    })
    Assert-Throws {
        Invoke-NvpnOwnedUninstall $current -StartUninstaller { return 5 }
    } 'A failed current uninstaller did not abort migration.'

    Set-Content -LiteralPath (Join-Path $legacyDir 'nvpn.exe') -Value daemon
    $daemonCalls = @{ Stops = @(); Services = @(); Kills = @() }
    Stop-NvpnBackgroundProcesses `
        -InstallLocations @($legacyDir, $currentDir, (Join-Path $root 'absent-dir')) `
        -StopDaemonViaCli { param($NvpnExe) $daemonCalls.Stops += $NvpnExe }.GetNewClosure() `
        -StopService { param($ServiceName) $daemonCalls.Services += $ServiceName }.GetNewClosure() `
        -GetNvpnProcesses { return @('nvpn-a', 'nvpn-b') }.GetNewClosure() `
        -KillNvpnProcesses { param($Processes) $daemonCalls.Kills += @($Processes) }.GetNewClosure()
    Assert-True ($daemonCalls.Stops.Count -eq 1 -and
        $daemonCalls.Stops[0] -ieq (Join-Path $legacyDir 'nvpn.exe')) 'Daemon stop skipped the owned nvpn.exe or hit foreign locations.'
    Assert-True ($daemonCalls.Services.Count -eq 1 -and $daemonCalls.Services[0] -ceq 'NvpnService') 'Migration did not stop NvpnService.'
    Assert-True ($daemonCalls.Kills.Count -eq 2) 'Leftover nvpn processes were not force-killed.'

    Write-Output 'WINDOWS_INSTALLER_MIGRATION_UNIT_OK'
} finally {
    Remove-Item -Recurse -Force -LiteralPath $root -ErrorAction SilentlyContinue
}
