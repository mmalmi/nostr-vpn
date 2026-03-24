<#
.SYNOPSIS
    Build nostr-vpn Android APK on Windows.

.DESCRIPTION
    Sets up environment variables and runs the Tauri Android build.
    Edit the paths below to match your system before running.

.EXAMPLE
    .\scripts\build_android_windows.ps1
    .\scripts\build_android_windows.ps1 -Target x86_64 -Debug
#>

param(
    [ValidateSet("aarch64", "armv7", "x86_64", "i686")]
    [string]$Target = "aarch64",

    [switch]$Debug
)

$ErrorActionPreference = "Continue"

# ──────────────────────────────────────────────
# CONFIGURATION — Edit these paths for your system
# ──────────────────────────────────────────────

$JavaHome   = "C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot"
$SdkRoot    = "$env:LOCALAPPDATA\Android\Sdk"

# Auto-detect NDK version (picks the latest installed)
$NdkBase = Join-Path $SdkRoot "ndk"
if (Test-Path $NdkBase) {
    $NdkVersion = Get-ChildItem $NdkBase -Directory | Sort-Object Name -Descending | Select-Object -First 1
    $NdkHome = $NdkVersion.FullName
} else {
    Write-Error "No NDK found in $NdkBase. Install via: sdkmanager --install 'ndk;28.2.13676358'"
    exit 1
}

# ──────────────────────────────────────────────
# ENVIRONMENT
# ──────────────────────────────────────────────

$env:JAVA_HOME        = $JavaHome
$env:ANDROID_HOME     = $SdkRoot
$env:ANDROID_SDK_ROOT = $SdkRoot
$env:NDK_HOME         = $NdkHome
$env:ANDROID_NDK_HOME = $NdkHome
$env:PATH             = "$JavaHome\bin;C:\Program Files\nodejs;$env:APPDATA\npm;$env:PATH"

# ──────────────────────────────────────────────
# PREFLIGHT CHECKS
# ──────────────────────────────────────────────

Write-Host "`n=== Preflight checks ===" -ForegroundColor Cyan

$checks = @(
    @{ Name = "Rust";    Cmd = "rustc --version" },
    @{ Name = "Cargo";   Cmd = "cargo --version" },
    @{ Name = "Java";    Cmd = "java -version 2>&1 | Select-Object -First 1" },
    @{ Name = "Node";    Cmd = "node --version" },
    @{ Name = "pnpm";    Cmd = "pnpm --version" }
)

$failed = $false
foreach ($c in $checks) {
    try {
        $result = Invoke-Expression $c.Cmd 2>&1 | Select-Object -First 1
        Write-Host "  [OK] $($c.Name): $result" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] $($c.Name): not found" -ForegroundColor Red
        $failed = $true
    }
}

# Check Android targets
$targets = rustup target list --installed 2>&1
if ($targets -notmatch "aarch64-linux-android") {
    Write-Host "  [FAIL] Rust Android targets not installed" -ForegroundColor Red
    Write-Host "         Run: rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android" -ForegroundColor Yellow
    $failed = $true
} else {
    Write-Host "  [OK] Rust Android targets installed" -ForegroundColor Green
}

if (-not (Test-Path $NdkHome)) {
    Write-Host "  [FAIL] NDK not found at $NdkHome" -ForegroundColor Red
    $failed = $true
} else {
    Write-Host "  [OK] NDK: $NdkHome" -ForegroundColor Green
}

if ($failed) {
    Write-Host "`nFix the issues above before building. See docs/android-build-windows.md" -ForegroundColor Red
    exit 1
}

# ──────────────────────────────────────────────
# FIND PROJECT ROOT
# ──────────────────────────────────────────────

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

if (-not (Test-Path (Join-Path $ProjectRoot "Cargo.toml"))) {
    Write-Error "Cannot find project root. Run this script from the repo's scripts/ directory."
    exit 1
}

Set-Location $ProjectRoot

# ──────────────────────────────────────────────
# INSTALL FRONTEND DEPENDENCIES
# ──────────────────────────────────────────────

Write-Host "`n=== Installing frontend dependencies ===" -ForegroundColor Cyan
pnpm --dir crates/nostr-vpn-gui install --frozen-lockfile
if ($LASTEXITCODE -ne 0) {
    Write-Error "pnpm install failed."
    exit 1
}

# ──────────────────────────────────────────────
# BUILD
# ──────────────────────────────────────────────

$buildArgs = @("--dir", "crates/nostr-vpn-gui", "exec", "tauri", "android", "build", "--target", $Target, "--apk")

if ($Debug) {
    $buildArgs += "--debug"
    Write-Host "`n=== Building DEBUG APK (target: $Target) ===" -ForegroundColor Cyan
} else {
    $buildArgs += "--ci"
    Write-Host "`n=== Building RELEASE APK (target: $Target) ===" -ForegroundColor Cyan
}

& pnpm @buildArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed. Check the output above for errors."
    exit 1
}

# ──────────────────────────────────────────────
# LOCATE OUTPUT
# ──────────────────────────────────────────────

$apkDir = Join-Path $ProjectRoot "crates\nostr-vpn-gui\src-tauri\gen\android\app\build\outputs\apk"
$apks = Get-ChildItem -Path $apkDir -Recurse -Filter "*.apk" -ErrorAction SilentlyContinue

Write-Host "`n=== Build complete ===" -ForegroundColor Green
if ($apks) {
    foreach ($apk in $apks) {
        $sizeMB = [math]::Round($apk.Length / 1MB, 1)
        Write-Host "  $($apk.FullName) ($sizeMB MB)" -ForegroundColor White
    }
} else {
    Write-Host "  APK not found — check build output for errors." -ForegroundColor Yellow
}

Write-Host "`nTo sign and install, run: .\scripts\sign_and_install_android.ps1" -ForegroundColor Cyan
