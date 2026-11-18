param(
    [Parameter(Mandatory=$true)][string]$BuildScript,
    [Parameter(Mandatory=$true)][string]$CrateArchive
)
# Runs the real compiled build script against isolated cache fixtures.
$ErrorActionPreference = 'Stop'
$Repo = Split-Path $PSScriptRoot -Parent
$Lock = [IO.File]::ReadAllText((Join-Path $Repo 'Cargo.lock'))
$Locked = [regex]::Matches($Lock, '(?m)^name = "wintun"\r?\nversion = "([^"]+)"\r?\nsource = "[^"]+"\r?\nchecksum = "([0-9a-f]{64})"')
if ($Locked.Count -ne 1) { throw 'Expected one locked Wintun registry package' }
$Version = $Locked[0].Groups[1].Value
$ArchiveHash = $Locked[0].Groups[2].Value
if ((Get-FileHash -LiteralPath $CrateArchive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ArchiveHash) {
    throw 'Crate archive SHA-256 does not match Cargo.lock'
}
$Package = 'wintun-' + $Version
$Crate = Join-Path $Repo 'crates\nostr-vpn-wintun'
$Manifest = [IO.File]::ReadAllText((Join-Path $Crate 'Cargo.toml'))
$Source = [IO.File]::ReadAllText((Join-Path $Crate 'build.rs'))
if ($Manifest -notmatch ('(?m)^wintun = "=' + [regex]::Escape($Version) + '"\r?$') -or
    !$Source.Contains(('const WINTUN_PACKAGE: &str = "' + $Package + '";')) -or
    !$Source.Contains($ArchiveHash)) { throw 'Build input pins do not match Cargo.lock' }
$BuildScript = (Resolve-Path -LiteralPath $BuildScript).Path
$CrateArchive = (Resolve-Path -LiteralPath $CrateArchive).Path
$Temp = Join-Path ([IO.Path]::GetTempPath()) ('nvpn-wintun-inputs-' + [Guid]::NewGuid().ToString('N'))
$OriginalEnvironment = @{}
foreach ($Name in @('CARGO_HOME','OUT_DIR','PROFILE','CARGO_CFG_TARGET_OS','CARGO_CFG_TARGET_ARCH')) {
    $OriginalEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw $Message }
}
function Get-Hash([string]$Path) {
    if (Test-Path -LiteralPath $Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
    return $null
}
function Seed([string]$RegistryName='registry-a', [string]$PackageName=$Package, [string]$Arch='amd64', [byte[]]$Bytes=$null) {
    $Path = Join-Path $script:Registry ($RegistryName + '\' + $PackageName + '\wintun\bin\' + $Arch + '\wintun.dll')
    [IO.Directory]::CreateDirectory((Split-Path $Path -Parent)) | Out-Null
    if ($null -eq $Bytes) { $Bytes = $Dlls[$Arch] }
    [IO.File]::WriteAllBytes($Path, $Bytes)
    return $Path
}
function Run-Build([string]$Arch='x86_64', [string]$TargetOs='windows', [string]$ExpectedError='') {
    $Before = Get-Hash $script:Output
    $env:CARGO_HOME = Join-Path $script:CaseRoot 'cargo'
    $env:OUT_DIR = $script:Out
    $env:PROFILE = 'debug'
    $env:CARGO_CFG_TARGET_OS = $TargetOs
    $env:CARGO_CFG_TARGET_ARCH = $Arch
    # This script has no child processes; wait only for this exact executable.
    $Info = New-Object System.Diagnostics.ProcessStartInfo
    $Info.FileName = $BuildScript
    $Info.UseShellExecute = $false
    $Info.CreateNoWindow = $true
    $Info.RedirectStandardOutput = $true
    $Info.RedirectStandardError = $true
    $Process = [Diagnostics.Process]::Start($Info)
    $Stdout = $Process.StandardOutput.ReadToEndAsync()
    $Stderr = $Process.StandardError.ReadToEndAsync()
    if (!$Process.WaitForExit(10000)) {
        $Process.Kill()
        $Process.WaitForExit()
        throw 'Build-script fixture exceeded 10 seconds'
    }
    $Code = $Process.ExitCode
    $Text = $Stdout.GetAwaiter().GetResult()
    $ErrorText = $Stderr.GetAwaiter().GetResult()
    $Process.Dispose()
    Assert-True ($null -ne $Code) 'Fixture exit code was not captured'
    if ($ExpectedError) {
        Assert-True ($Code -ne 0) ('Expected failure: ' + $ExpectedError)
        Assert-True ($ErrorText.Contains($ExpectedError)) ('Wrong error: ' + $ErrorText)
        Assert-True (!$Text.Contains('cargo:rustc-env=NOSTR_VPN_WINTUN_DLL_SOURCE=')) 'Failure advertised a DLL output'
        Assert-True ((Get-Hash $script:Output) -ceq $Before) 'Failure changed the output DLL'
    } else {
        Assert-True ($Code -eq 0) ('Build script failed: ' + $ErrorText)
        if ($TargetOs -eq 'windows') {
            Assert-True ($Text.Contains('cargo:rustc-env=NOSTR_VPN_WINTUN_DLL_SOURCE=' + $script:Output)) 'Output layout changed'
        }
    }
}
function Assert-Output([string]$Arch='amd64') {
    Assert-True ((Get-Hash $script:Output) -ceq $DllHashes[$Arch]) 'Output differs from the verified archive'
}

$Cases = @(
    @{Name='all architecture hashes match locked archive'; Run={
        foreach ($Arch in ([ordered]@{x86='x86'; x86_64='amd64'; arm='arm'; aarch64='arm64'}).GetEnumerator()) {
            Seed -Arch $Arch.Value | Out-Null
            Run-Build -Arch $Arch.Key
            Assert-Output $Arch.Value
        }
    }},
    @{Name='wrong version is not used'; Run={
        Seed -PackageName 'wintun-0.5.0' | Out-Null
        Run-Build -ExpectedError 'not found'
    }},
    @{Name='unrelated bindings package is not used'; Run={
        Seed -PackageName 'wintun-bindings-0.7.40' | Out-Null
        Run-Build -ExpectedError 'not found'
    }},
    @{Name='exact package wins over other cached packages'; Run={
        Seed -PackageName 'wintun-0.5.0' -Bytes ([byte[]](1,2,3)) | Out-Null
        Seed -PackageName 'wintun-bindings-0.7.40' -Bytes ([byte[]](4,5,6)) | Out-Null
        Seed | Out-Null
        Run-Build
        Assert-Output
    }},
    @{Name='changed DLL fails without replacing existing output'; Run={
        Seed -Bytes ([byte[]](1,2,3)) | Out-Null
        [IO.File]::WriteAllText($script:Output, 'existing output')
        Run-Build -ExpectedError 'SHA-256 mismatch'
    }},
    @{Name='wrong architecture bytes fail'; Run={
        Seed -Bytes $Dlls['arm64'] | Out-Null
        Run-Build -ExpectedError 'SHA-256 mismatch'
    }},
    @{Name='conflicting registry copies fail in either order'; Run={
        foreach ($Valid in @('registry-a','registry-b')) {
            $Invalid = if ($Valid -eq 'registry-a') {'registry-b'} else {'registry-a'}
            Seed -RegistryName $Valid | Out-Null
            Seed -RegistryName $Invalid -Bytes ([byte[]](1,2,3)) | Out-Null
            Run-Build -ExpectedError 'SHA-256 mismatch'
        }
    }},
    @{Name='identical verified registry copies are accepted'; Run={
        Seed -RegistryName 'registry-a' | Out-Null
        Seed -RegistryName 'registry-b' | Out-Null
        Run-Build
        Assert-Output
    }},
    @{Name='missing DLL fails'; Run={
        Remove-Item -LiteralPath (Seed)
        Run-Build -ExpectedError 'failed to read pinned'
    }},
    @{Name='missing registry fails'; Run={
        Remove-Item -LiteralPath $script:Registry
        Run-Build -ExpectedError 'failed to read'
    }},
    @{Name='unsupported architecture fails'; Run={
        Seed | Out-Null
        Run-Build -Arch 'riscv64' -ExpectedError 'unsupported windows arch'
    }},
    @{Name='stale output is replaced and current output is preserved'; Run={
        Seed | Out-Null
        [IO.File]::WriteAllText($script:Output, 'stale output')
        Run-Build
        Assert-Output
        $Before = (Get-Item -LiteralPath $script:Output).LastWriteTimeUtc.Ticks
        Run-Build
        Assert-True ((Get-Item -LiteralPath $script:Output).LastWriteTimeUtc.Ticks -eq $Before) 'Current DLL was rewritten'
    }},
    @{Name='non-Windows build does not require Wintun'; Run={
        Remove-Item -LiteralPath $script:Registry
        Run-Build -TargetOs 'linux'
        Assert-True (!(Test-Path -LiteralPath $script:Output)) 'Non-Windows build copied a DLL'
    }}
)
$Results = @()
try {
    [IO.Directory]::CreateDirectory($Temp) | Out-Null
    # Extract only the four named DLLs from the already verified archive.
    $Members = @('x86','amd64','arm','arm64') | ForEach-Object { $Package + '/wintun/bin/' + $_ + '/wintun.dll' }
    & tar.exe -xf $CrateArchive -C $Temp @Members
    if ($LASTEXITCODE -ne 0) { throw 'Could not extract verified crate DLLs' }
    $Dlls = @{}
    $DllHashes = @{}
    foreach ($Arch in @('x86','amd64','arm','arm64')) {
        $Path = Join-Path $Temp ($Package + '\wintun\bin\' + $Arch + '\wintun.dll')
        $Dlls[$Arch] = [IO.File]::ReadAllBytes($Path)
        $DllHashes[$Arch] = Get-Hash $Path
    }
    foreach ($Case in $Cases) {
        $script:CaseRoot = Join-Path $Temp ('case-' + $Results.Count)
        $script:Registry = Join-Path $script:CaseRoot 'cargo\registry\src'
        $script:Out = Join-Path $script:CaseRoot 'target\debug\build\fixture\out'
        $script:Output = Join-Path $script:CaseRoot 'target\debug\wintun.dll'
        [IO.Directory]::CreateDirectory($script:Registry) | Out-Null
        [IO.Directory]::CreateDirectory($script:Out) | Out-Null
        try {
            & $Case.Run
            $Results += @{name=$Case.Name; passed=$true}
            Write-Output ('PASS ' + $Case.Name)
        } catch {
            $Results += @{name=$Case.Name; passed=$false; error=$_.Exception.Message}
            Write-Output ('FAIL ' + $Case.Name + ': ' + $_.Exception.Message)
        }
    }
    $Failures = @($Results | Where-Object { !$_.passed })
    @{archiveSha256=$ArchiveHash; buildScriptSha256=(Get-Hash $BuildScript); cases=$Results; passed=($Results.Count-$Failures.Count); failed=$Failures.Count} | ConvertTo-Json -Depth 5
    if ($Failures.Count) { throw "$($Failures.Count) Wintun fixture cases failed" }
} finally {
    foreach ($Name in $OriginalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($Name, $OriginalEnvironment[$Name], 'Process')
    }
    if (Test-Path -LiteralPath $Temp) { Remove-Item -LiteralPath $Temp -Recurse -Force }
}
