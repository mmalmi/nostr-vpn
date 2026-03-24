# Building nostr-vpn for Android on Windows

This guide walks through setting up a complete Android build environment on Windows and producing a signed APK from the existing codebase.

> The Android port is already fully implemented in the repo. This document covers **environment setup and build reproduction only**.

---

## Prerequisites

| Tool | Minimum version | Purpose |
|------|----------------|---------|
| Rust (stable) | 1.78+ | Compiler + cross-compilation targets |
| JDK | 17 | Android Gradle toolchain |
| Node.js | 22 LTS+ | Frontend build (Vite/Svelte) |
| pnpm | 8+ | Package manager for frontend |
| Android SDK | API 34+ | Android platform |
| Android NDK | r28c (28.2.x) | Native cross-compilation |
| Android Build-Tools | 34.0+ | APK signing (`apksigner`) |
| Tauri CLI | 2.x | Build orchestration |

---

## Step 1 — Rust and Android targets

If Rust is not installed, get it from [rustup.rs](https://rustup.rs/).

```powershell
# Add all Android cross-compilation targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
```

Verify:

```powershell
rustup target list --installed | Select-String android
# Should list all four targets
```

## Step 2 — JDK 17

Android Gradle requires JDK 17 (not 8, not 21).

```powershell
winget install EclipseAdoptium.Temurin.17.JDK --accept-source-agreements --accept-package-agreements
```

Default install path: `C:\Program Files\Eclipse Adoptium\jdk-17.x.x-hotspot`

## Step 3 — Node.js and pnpm

```powershell
# Node.js LTS
winget install OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements

# pnpm (after restarting your terminal so node is in PATH)
npm install -g pnpm
```

## Step 4 — Android SDK, NDK, and platform tools

If you already have Android Studio installed, use its SDK Manager. Otherwise, install the command-line tools manually:

```powershell
# Download cmdline-tools
Invoke-WebRequest -Uri "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip" -OutFile cmdline-tools.zip
Expand-Archive cmdline-tools.zip -DestinationPath "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools"
Rename-Item "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\cmdline-tools" "latest"
Remove-Item cmdline-tools.zip

# Install NDK, platform, and build-tools
$sdkmanager = "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin\sdkmanager.bat"
& $sdkmanager --install "ndk;28.2.13676358" "platforms;android-36" "build-tools;36.0.0" "platform-tools"
```

Accept all licenses when prompted.

## Step 5 — Tauri CLI

```powershell
cargo install tauri-cli --version "^2"
```

## Step 6 — Environment variables

Add these to your PowerShell profile (`$PROFILE`) or set them before each build session:

```powershell
$env:JAVA_HOME        = "C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot"
$env:ANDROID_HOME     = "$env:LOCALAPPDATA\Android\Sdk"
$env:ANDROID_SDK_ROOT = "$env:LOCALAPPDATA\Android\Sdk"
$env:NDK_HOME         = "$env:LOCALAPPDATA\Android\Sdk\ndk\28.2.13676358"
$env:ANDROID_NDK_HOME = "$env:LOCALAPPDATA\Android\Sdk\ndk\28.2.13676358"
$env:PATH             = "$env:JAVA_HOME\bin;C:\Program Files\nodejs;$env:APPDATA\npm;$env:PATH"
```

> **Adjust paths** to match your actual installed versions. The JDK and NDK version numbers in the paths will differ on your machine.

## Step 7 — Verify everything

```powershell
rustc --version              # 1.78+
java -version                # 17.x
node --version               # 22.x+
pnpm --version               # 8.x+
cargo tauri --version         # 2.x
adb --version                # present
echo $env:NDK_HOME           # points to NDK directory
```

---

## Building the APK

### Install frontend dependencies

```powershell
pnpm --dir crates/nostr-vpn-gui install --frozen-lockfile
```

### Build (debug)

```powershell
pnpm --dir crates/nostr-vpn-gui exec tauri android build --target aarch64 --apk --debug
```

### Build (release)

```powershell
pnpm --dir crates/nostr-vpn-gui exec tauri android build --target aarch64 --apk --ci
```

The APK lands at:

```
crates/nostr-vpn-gui/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk
```

> Use `--target aarch64` for modern phones (95%+ of devices). Omit `--target` to build for all architectures (larger APK).

---

## Signing and installing

The release APK is unsigned. Sign it before installing on a device.

### Quick sign with debug keystore

```powershell
$buildTools = "$env:LOCALAPPDATA\Android\Sdk\build-tools\36.0.0"
$debugKs    = "$env:USERPROFILE\.android\debug.keystore"

# Generate debug keystore if it doesn't exist
if (-not (Test-Path $debugKs)) {
    keytool -genkey -v -keystore $debugKs -storepass android -alias androiddebugkey `
      -keypass android -keyalg RSA -keysize 2048 -validity 10000 `
      -dname "CN=Android Debug,O=Android,C=US"
}

# Sign
& "$buildTools\apksigner.bat" sign `
  --ks $debugKs --ks-key-alias androiddebugkey `
  --ks-pass pass:android --key-pass pass:android `
  --out app-signed.apk app-universal-release-unsigned.apk

# Install on connected device
adb install -r app-signed.apk
```

### Production signing (for Play Store)

```powershell
# Generate a release keystore (do this once, keep it safe)
keytool -genkey -v -keystore nostr-vpn-release.jks -alias nostr-vpn `
  -keyalg RSA -keysize 2048 -validity 10000

# Sign with release key
& "$buildTools\apksigner.bat" sign `
  --ks nostr-vpn-release.jks --ks-key-alias nostr-vpn `
  --out app-release-signed.apk app-universal-release-unsigned.apk
```

---

## Automated scripts

Two PowerShell scripts are provided in `scripts/` for convenience:

- **`build_android_windows.ps1`** — Sets up environment and runs the full build
- **`sign_and_install_android.ps1`** — Signs the APK and installs it on a connected device

Edit the paths at the top of each script to match your system, then run:

```powershell
.\scripts\build_android_windows.ps1
.\scripts\sign_and_install_android.ps1
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `linker cc not found` for android target | Missing NDK linker config | Tauri handles this automatically via `NDK_HOME`. Make sure the env var is set. |
| `Unable to find OpenSSL` | openssl-sys can't find Android OpenSSL | The project uses `rustls` — ensure no dependency pulls in `openssl-sys`. |
| APK won't install ("not signed") | Android rejects unsigned APKs | Sign with `apksigner` (see above). |
| `JAVA_HOME` not recognized | JDK path wrong or not set | Verify `java -version` prints 17.x with the correct `JAVA_HOME`. |
| Gradle fails with "SDK not found" | `ANDROID_HOME` not set | Set both `ANDROID_HOME` and `ANDROID_SDK_ROOT`. |
| `ring` build failure | Old `ring` version incompatible with NDK r28 | Update `ring` to 0.17+ or use a `[patch]` in Cargo.toml. |

---

## Architecture reference

The built APK contains:

```
APK
├── lib/arm64-v8a/libnostr_vpn_gui_lib.so   ← Core Rust (Nostr signaling + WireGuard via boringtun)
├── assets/                                   ← Frontend Svelte (HTML/JS/CSS via Vite)
└── classes.dex                               ← Kotlin (VpnService + Tauri plugin bridge)
```

Runtime flow:

```
UI (Svelte/WebView)
  → Tauri invoke (JS → Rust)
  → android_session.rs (Nostr signaling, peer management)
  → android_vpn.rs (Tauri plugin bridge to Kotlin)
  → NostrVpnPlugin.kt (prepare/start/stop/status)
  → NostrVpnService.kt (Android VpnService, TUN fd)
  → mobile_wg.rs (boringtun userspace WireGuard)
  → Android OS TUN driver
```
