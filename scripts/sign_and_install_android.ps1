<#
.SYNOPSIS
    Sign and install a nostr-vpn Android APK on a connected device.

.DESCRIPTION
    Signs the release APK with a debug or release keystore and installs it
    via adb on a connected Android device.

.EXAMPLE
    .\scripts\sign_and_install_android.ps1
    .\scripts\sign_and_install_android.ps1 -Release -Keystore .\my-release.jks -KeyAlias mykey
#>

param(
    [switch]$Release,

    [string]$Keystore,

    [string]$KeyAlias,

    [switch]$SkipInstall
)

$ErrorActionPreference = "Continue"

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────

$JavaHome   = "C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot"
$SdkRoot    = "$env:LOCALAPPDATA\Android\Sdk"

$env:JAVA_HOME = $JavaHome
$env:PATH      = "$JavaHome\bin;$env:PATH"

# Auto-detect build-tools version
$btBase = Join-Path $SdkRoot "build-tools"
$btVersion = Get-ChildItem $btBase -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $btVersion) {
    Write-Error "No build-tools found in $btBase"
    exit 1
}
$apkSignerPath = Join-Path $btVersion.FullName "apksigner.bat"

$adbPath = Join-Path $SdkRoot "platform-tools\adb.exe"

# ──────────────────────────────────────────────
# FIND APK
# ──────────────────────────────────────────────

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$apkDir = Join-Path $ProjectRoot "crates\nostr-vpn-gui\src-tauri\gen\android\app\build\outputs\apk"

$unsignedApk = Get-ChildItem -Path $apkDir -Recurse -Filter "*unsigned*" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $unsignedApk) {
    # Fall back to any release APK
    $unsignedApk = Get-ChildItem -Path $apkDir -Recurse -Filter "*release*.apk" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

if (-not $unsignedApk) {
    Write-Error "No APK found. Run build_android_windows.ps1 first."
    exit 1
}

Write-Host "Found APK: $($unsignedApk.FullName)" -ForegroundColor Cyan

$signedApk = Join-Path $unsignedApk.DirectoryName "app-signed.apk"

# ──────────────────────────────────────────────
# KEYSTORE
# ──────────────────────────────────────────────

if ($Release) {
    if (-not $Keystore) {
        Write-Error "Release signing requires -Keystore path."
        exit 1
    }
    if (-not $KeyAlias) {
        Write-Error "Release signing requires -KeyAlias."
        exit 1
    }
    $ksPath  = $Keystore
    $ksAlias = $KeyAlias
    # Prompt for passwords interactively
    $ksPass  = Read-Host "Keystore password" -AsSecureString
    $keyPass = Read-Host "Key password" -AsSecureString
    $ksPassPlain  = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ksPass))
    $keyPassPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($keyPass))

    Write-Host "`n=== Signing with RELEASE keystore ===" -ForegroundColor Yellow
    & $apkSignerPath sign `
        --ks $ksPath --ks-key-alias $ksAlias `
        --ks-pass "pass:$ksPassPlain" --key-pass "pass:$keyPassPlain" `
        --out $signedApk $unsignedApk.FullName
} else {
    $debugKs = Join-Path $env:USERPROFILE ".android\debug.keystore"

    # Generate debug keystore if needed
    if (-not (Test-Path $debugKs)) {
        Write-Host "Generating debug keystore at $debugKs" -ForegroundColor Yellow
        $debugDir = Split-Path $debugKs
        if (-not (Test-Path $debugDir)) { New-Item -ItemType Directory -Path $debugDir -Force | Out-Null }

        keytool -genkey -v -keystore $debugKs -storepass android -alias androiddebugkey `
            -keypass android -keyalg RSA -keysize 2048 -validity 10000 `
            -dname "CN=Android Debug,O=Android,C=US"
    }

    Write-Host "`n=== Signing with DEBUG keystore ===" -ForegroundColor Cyan
    & $apkSignerPath sign `
        --ks $debugKs --ks-key-alias androiddebugkey `
        --ks-pass pass:android --key-pass pass:android `
        --out $signedApk $unsignedApk.FullName
}

if ($LASTEXITCODE -ne 0) {
    Write-Error "Signing failed."
    exit 1
}

$sizeMB = [math]::Round((Get-Item $signedApk).Length / 1MB, 1)
Write-Host "Signed APK: $signedApk ($sizeMB MB)" -ForegroundColor Green

# ──────────────────────────────────────────────
# INSTALL
# ──────────────────────────────────────────────

if ($SkipInstall) {
    Write-Host "`nSkipping install (-SkipInstall). APK ready at: $signedApk" -ForegroundColor Cyan
    exit 0
}

# Check for connected device
$devices = & $adbPath devices 2>&1
$connected = ($devices | Select-String "device$" | Measure-Object).Count

if ($connected -eq 0) {
    Write-Host "`nNo Android device connected. Connect via USB and enable USB debugging." -ForegroundColor Yellow
    Write-Host "APK ready at: $signedApk" -ForegroundColor Cyan
    exit 0
}

Write-Host "`n=== Installing on device ===" -ForegroundColor Cyan
& $adbPath install -r $signedApk

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nInstalled successfully!" -ForegroundColor Green
} else {
    Write-Host "`nInstall failed. Try: adb uninstall <package-name> first, then retry." -ForegroundColor Red
    exit 1
}
