# Android

The Android app is a Kotlin/Jetpack Compose shell over
`nostr-vpn-app-core`. JNI calls the shared JSON C ABI, and
`NostrVpnService` connects Android's TUN interface to the Rust mobile tunnel.
The current build targets Android 8.0+ (`minSdk 26`) on `arm64-v8a`.

The source of truth for cross-platform behavior is the
[native UI parity matrix](../docs/native-ui-parity-matrix.md).

## Build and install

Install the Android SDK/NDK, Rust, `cargo-ndk`, and Gradle, then run from the
repository root:

```sh
just android-build
just android-install
```

`android-build` compiles the Rust core and packages a debug APK. `android-install`
installs that APK on the selected adb target.

## Smoke tests

```sh
just android-smoke
just android-smoke-vpn
```

The first command builds, installs, launches, and checks the current app. The VPN
variant also exercises Android VPN permission, the foreground `VpnService`, the
Rust runtime, and native TUN counters. A fresh install needs an active Nostr VPN
network; for isolated OS/TUN coverage, use:

```sh
./scripts/mobile-android-smoke.sh \
  --create-network --accept-vpn-dialog --vpn-cycle
```

Only use `--accept-vpn-dialog` on a trusted test device. Set
`NVPN_ANDROID_SERIAL` (or `ANDROID_SERIAL`) when adb exposes more than one target.
VPN evidence is written under `artifacts/mobile-android/`.

For shared, simulator, physical-device, and exit-path coverage, see the
[mobile test kit](../docs/mobile-test-kit.md).
